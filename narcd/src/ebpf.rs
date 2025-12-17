use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use aya::{
    Ebpf,
    maps::{
        MapData, PerfEventArray,
        perf::{Events, PerfEventArrayBuffer},
    },
    programs::{Xdp, XdpFlags},
    util::online_cpus,
};
use bytes::BytesMut;
use default_net::get_default_interface;
use narcd_common::Flow;
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc::{self, UnboundedReceiver},
};

use crate::logger::EventLogger;

const EVENTS_READ_BUF_SIZE: usize = 10;

pub async fn start_ebpf<L: EventLogger<Flow> + 'static>(logger: L) -> Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/narcd"
    )))?;

    let iface = get_default_interface()
        .map_err(|error| anyhow!(error))?
        .name;

    let program: &mut Xdp = ebpf
        .program_mut("narcd")
        .context("Could not locate narcd eBPF program")?
        .try_into()
        .context("narcd eBPF program is not XDP")?;

    program.load()?;

    log::info!("Attempting to attach eBPF program to interface {}", iface);
    program
        .attach(&iface, XdpFlags::default())
        .context("Failed to attach the XDP program with default flags")?;

    let mut events: PerfEventArray<_> = ebpf
        .take_map("EVENTS")
        .context("narcd-ebpf did not declare an EVENTS array")?
        .try_into()
        .context("EVENTS map is not PerfEventArray")?;

    let collector = FlowCollector::new(logger);
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let buf = events.open(cpu_id, None)?;
        let fd = AsyncFd::with_interest(buf, Interest::READABLE)?;
        tokio::spawn(read_event_buffer(fd, collector.clone()));
    }

    log::info!("eBPF program loaded and attached to interface {}", iface);

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[derive(Clone)]
struct FlowCollector {
    tx: mpsc::UnboundedSender<Flow>,
}

impl FlowCollector {
    pub fn new<L: EventLogger<Flow> + 'static>(logger: L) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Flow>();
        tokio::spawn(run_flow_collector(rx, logger));
        Self { tx }
    }

    pub fn collect_flow(&self, flow: Flow) -> Result<()> {
        self.tx.send(flow)?;
        Ok(())
    }
}

async fn run_flow_collector<L: EventLogger<Flow>>(mut rx: UnboundedReceiver<Flow>, logger: L) {
    while let Some(flow) = rx.recv().await {
        logger
            .log_event(flow)
            .await
            .inspect_err(|err| log::error!("Failed to log flow: {:?}", err))
            .ok();
    }

    log::warn!("Scan tracker is shutting down");
}

async fn read_event_buffer(
    mut fd: AsyncFd<PerfEventArrayBuffer<MapData>>,
    tracker: FlowCollector,
) -> ! {
    let buf_sz = core::mem::size_of::<Flow>();
    let mut buffers = std::iter::repeat_with(|| BytesMut::with_capacity(buf_sz))
        .take(EVENTS_READ_BUF_SIZE)
        .collect::<Vec<_>>();

    loop {
        let mut guard = fd.readable_mut().await.unwrap();
        loop {
            let Events { read, .. } = guard.get_inner_mut().read_events(&mut buffers).unwrap();

            for buf in buffers.iter_mut().take(read) {
                let ptr = buf.as_ptr() as *const Flow;
                let flow = unsafe { ptr.read_unaligned() };
                tracker
                    .collect_flow(flow)
                    .inspect_err(|err| log::error!("Failed to collect flow {:?}", err))
                    .ok();
            }

            if read != buffers.len() {
                break;
            }
        }
        guard.clear_ready();
    }
}
