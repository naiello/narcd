use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

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
use chrono::Utc;
use default_net::get_default_interface;
use narcd_common::{Flow, FlowType};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc::{self, UnboundedReceiver},
};

use crate::{events::PortScan, logger::EventLogger, metadata::Metadata, util::partition_hashmap};

const EVENTS_READ_BUF_SIZE: usize = 10;
const FLOW_COLLECTOR_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const FLOW_STALE_THRESHOLD: Duration = Duration::from_secs(16);
const UNIQUE_PORTS_THRESHOLD: usize = 1;

pub async fn start_ebpf<L: EventLogger<PortScan> + 'static>(
    metadata: Arc<Metadata>,
    logger: L,
) -> Result<()> {
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

    let collector = FlowCollector::new(logger, metadata);
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
    pub fn new<L: EventLogger<PortScan> + 'static>(logger: L, metadata: Arc<Metadata>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Flow>();
        tokio::spawn(run_flow_collector(rx, logger, metadata.clone()));
        Self { tx }
    }

    pub fn collect_flow(&self, flow: Flow) -> Result<()> {
        self.tx.send(flow)?;
        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash, Debug)]
struct TrackedScanKey {
    src_ip: IpAddr,
    scan_type: FlowType,
}

#[derive(PartialEq, Eq, Debug)]
struct TrackedScan {
    last_active: Instant,
    src_ports: BTreeSet<u16>,
    dst_ports: BTreeSet<u16>,
}

async fn run_flow_collector<L: EventLogger<PortScan>>(
    mut rx: UnboundedReceiver<Flow>,
    logger: L,
    metadata: Arc<Metadata>,
) {
    let mut sweeper = tokio::time::interval(FLOW_COLLECTOR_SWEEP_INTERVAL);
    let mut scans: HashMap<TrackedScanKey, TrackedScan> = HashMap::new();

    loop {
        tokio::select! {
            now = sweeper.tick() => {
                let now = now.into_std();
                let utcnow = Utc::now();

                let partitioned = partition_hashmap(
                    scans,
                    |_, scan| now.duration_since(scan.last_active) > FLOW_STALE_THRESHOLD,
                );
                let stale = partitioned.matches;
                scans = partitioned.not_matches;

                for (key, scan) in stale {
                    if scan.dst_ports.len() < UNIQUE_PORTS_THRESHOLD {
                        continue
                    }

                    let event = PortScan {
                        ts: utcnow,
                        dst_ports: scan.dst_ports.iter().copied().collect(),
                        metadata: metadata.as_ref().clone(),
                        src_ip: key.src_ip,
                        src_ports: scan.src_ports.iter().copied().collect(),
                        scan_type: key.scan_type,
                    };

                    logger.log_event(event)
                        .await
                        .inspect_err(|err| log::error!("Failed to log port scan: {:?}", err))
                        .ok();
                }
            },
            Some(flow) = rx.recv() => {
                let last_active = Instant::now();
                let key = TrackedScanKey {
                    src_ip: IpAddr::V4(flow.src_ip),
                    scan_type: flow.flow_type,
                };

                scans.entry(key)
                    .and_modify(|scan| {
                        scan.dst_ports.insert(flow.dst_port);
                        scan.src_ports.insert(flow.src_port);
                        scan.last_active = last_active;
                    })
                    .or_insert_with(|| TrackedScan {
                            last_active,
                            dst_ports: BTreeSet::from([flow.dst_port]),
                            src_ports: BTreeSet::from([flow.src_port]),
                        }
                    );
            },
            else => break,
        }
    }

    log::warn!("Flow collector is shutting down");
}

async fn read_event_buffer(
    mut fd: AsyncFd<PerfEventArrayBuffer<MapData>>,
    tracker: FlowCollector,
) -> ! {
    let buf_sz = size_of::<Flow>();
    let mut buffers = std::iter::repeat_with(|| BytesMut::with_capacity(buf_sz))
        .take(EVENTS_READ_BUF_SIZE)
        .collect::<Vec<_>>();

    loop {
        let mut guard = fd.readable_mut().await.unwrap();
        loop {
            let Events { read, .. } = guard.get_inner_mut().read_events(&mut buffers).unwrap();

            for buf in buffers.iter().take(read) {
                let flow = unsafe { (buf.as_ptr() as *const Flow).read_unaligned() };
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
