use std::{net::Ipv4Addr, time::Duration};

use anyhow::{anyhow, Context as _, Result};
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
use narcd_common::Flow;
use tokio::io::{unix::AsyncFd, Interest};
use default_net::get_default_interface;

const EVENTS_READ_BUF_SIZE: usize = 10;

pub async fn start_ebpf() -> Result<()> {
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

    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let buf = events.open(cpu_id, None)?;
        let fd = AsyncFd::with_interest(buf, Interest::READABLE)?;
        tokio::spawn(read_event_buffer(fd));
    }

    log::info!("eBPF program loaded and attached to interface {}", iface);

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn read_event_buffer(mut fd: AsyncFd<PerfEventArrayBuffer<MapData>>) -> ! {
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
                let ip = Ipv4Addr::from_bits(flow.src_ip);
                log::info!("SYN from {} on {}", ip, flow.dst_port);
            }

            if read != buffers.len() {
                break;
            }
        }
        guard.clear_ready();
    }
}
