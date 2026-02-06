use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail};
use aya::{
    Ebpf,
    maps::{
        HashMap as EbpfHashMap, MapData, PerfEventArray,
        perf::{Events, PerfEventArrayBuffer},
    },
    programs::{Xdp, XdpFlags},
    util::online_cpus,
};
use bytes::BytesMut;
use chrono::Utc;
use default_net::get_default_interface;
use narcd_common::{Flow, FlowType, PacketDisposition, PacketSource};
use tokio::{
    io::{Interest, unix::AsyncFd},
    select,
    sync::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    time,
};
use tokio_graceful::ShutdownGuard;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    events::PortScan, ipasn::IpAsnDb, ipgeo::IpGeoDb, logger::EventLogger, metadata::Metadata,
    rdns::ReverseDns, util::partition_hashmap,
};

const EVENTS_READ_BUF_SIZE: usize = 10;
const FLOW_COLLECTOR_SWEEP_INTERVAL: Duration = Duration::from_secs(5);
const FLOW_STALE_THRESHOLD: Duration = Duration::from_secs(16);
const UNIQUE_PORTS_THRESHOLD: usize = 1;

pub struct EbpfListener {
    _handle: AbortOnDropHandle<Result<()>>,
}

impl EbpfListener {
    pub async fn start<L: EventLogger<PortScan> + Sync + 'static>(
        metadata: Arc<Metadata>,
        logger: L,
        packet_disposition: HashMap<PacketSource, PacketDisposition>,
        ipasn_db: Arc<IpAsnDb>,
        ipgeo_db: Arc<IpGeoDb>,
        rdns: Arc<ReverseDns>,
        shutdown: ShutdownGuard,
    ) -> Result<Self> {
        let (ready_tx, ready_rx) = oneshot::channel::<()>();
        let task = shutdown.into_spawn_task_fn(|shutdown| async move {
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

            let mut pktdisp: EbpfHashMap<_, PacketSource, PacketDisposition> = ebpf
                .map_mut("PKTDISP")
                .context("narc-ebpf did not declare a PKTDISP array")?
                .try_into()
                .context("PKTDISP map is not HashMap")?;

            for (src, disp) in packet_disposition {
                pktdisp.insert(src, disp, 0).context(format!(
                    "Failed to insert ignore entry {:?} -> {:?}",
                    src, disp
                ))?;
            }

            let collector =
                FlowCollector::new(logger, metadata, ipasn_db, ipgeo_db, rdns, shutdown.clone());
            let mut tasks = Vec::new();
            for cpu_id in online_cpus().map_err(|(_, error)| error)? {
                let buf = events.open(cpu_id, None)?;
                let fd = AsyncFd::with_interest(buf, Interest::READABLE)?;
                let mut task = EventBufferReaderTask {
                    fd,
                    tracker: collector.clone(),
                };
                tasks.push(AbortOnDropHandle::new(
                    shutdown.spawn_task_fn(|guard| async move { task.run(guard).await }),
                ));
            }

            ready_tx
                .send(())
                .map_err(|_| anyhow!("failed to send ready signal"))?;

            shutdown.cancelled().await;
            log::info!("eBPF program shutting down");

            Ok(())
        });
        let handle = AbortOnDropHandle::new(task);

        match time::timeout(Duration::from_secs(2), ready_rx).await {
            Ok(Ok(())) => {
                log::info!("eBPF program loaded");
            }
            Ok(Err(_)) => {
                bail!("eBPF program failed to start")
            }
            Err(_) => {
                bail!("eBPF program timed out waiting to start")
            }
        }

        Ok(Self { _handle: handle })
    }
}

#[derive(Clone)]
struct FlowCollector {
    tx: mpsc::UnboundedSender<Flow>,
    _task: Arc<AbortOnDropHandle<()>>,
}

impl FlowCollector {
    pub fn new<L: EventLogger<PortScan> + Sync + 'static>(
        logger: L,
        metadata: Arc<Metadata>,
        ipasn_db: Arc<IpAsnDb>,
        ipgeo_db: Arc<IpGeoDb>,
        rdns: Arc<ReverseDns>,
        shutdown: ShutdownGuard,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Flow>();
        let mut task = FlowCollectorTask {
            logger,
            metadata,
            ipasn_db,
            ipgeo_db,
            rdns,
            scans: HashMap::new(),
            rx,
        };
        let handle = shutdown.into_spawn_task_fn(|guard| async move { task.run(guard).await });
        Self {
            tx,
            _task: Arc::new(AbortOnDropHandle::new(handle)),
        }
    }

    pub fn collect_flow(&self, flow: Flow) -> Result<()> {
        self.tx.send(flow)?;
        Ok(())
    }
}

struct FlowCollectorTask<L: EventLogger<PortScan> + Sync> {
    rx: UnboundedReceiver<Flow>,
    logger: L,
    metadata: Arc<Metadata>,
    ipasn_db: Arc<IpAsnDb>,
    ipgeo_db: Arc<IpGeoDb>,
    rdns: Arc<ReverseDns>,
    scans: HashMap<TrackedScanKey, TrackedScan>,
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

impl<L: EventLogger<PortScan> + Sync> FlowCollectorTask<L> {
    async fn sweep_stale_flows(&mut self, now: Instant) {
        let utcnow = Utc::now();

        let scans = std::mem::take(&mut self.scans);
        let partitioned = partition_hashmap(scans, |_, scan| {
            now.duration_since(scan.last_active) > FLOW_STALE_THRESHOLD
        });
        let stale = partitioned.matches;

        for (key, scan) in stale {
            if scan.dst_ports.len() < UNIQUE_PORTS_THRESHOLD {
                continue;
            }

            let src_ip_as = match key.src_ip {
                IpAddr::V4(ipv4) => self.ipasn_db.lookup(ipv4).await,
                _ => None,
            };

            let src_ip_geo = match key.src_ip {
                IpAddr::V4(ipv4) => self.ipgeo_db.lookup(ipv4).await,
                _ => None,
            };

            let src_hostname = match key.src_ip {
                IpAddr::V4(ipv4) => self.rdns.lookup(ipv4).await,
                _ => None,
            };

            let event = PortScan {
                ts: utcnow,
                dst_ports: scan.dst_ports.iter().copied().collect(),
                metadata: self.metadata.as_ref().clone(),
                src_ip: key.src_ip,
                src_ports: scan.src_ports.iter().copied().collect(),
                src_ip_as,
                src_ip_geo,
                src_hostname,
                scan_type: key.scan_type,
            };

            self.logger
                .log_event(event)
                .await
                .inspect_err(|err| log::error!("Failed to log port scan: {:?}", err))
                .ok();
        }

        self.scans = partitioned.not_matches
    }

    fn collect_flow(&mut self, flow: Flow) {
        let last_active = Instant::now();
        let key = TrackedScanKey {
            src_ip: IpAddr::V4(flow.src_ip),
            scan_type: flow.flow_type,
        };

        self.scans
            .entry(key)
            .and_modify(|scan| {
                scan.dst_ports.insert(flow.dst_port);
                scan.src_ports.insert(flow.src_port);
                scan.last_active = last_active;
            })
            .or_insert_with(|| TrackedScan {
                last_active,
                dst_ports: BTreeSet::from([flow.dst_port]),
                src_ports: BTreeSet::from([flow.src_port]),
            });
    }

    async fn run(&mut self, shutdown: ShutdownGuard) {
        let mut sweeper = time::interval(FLOW_COLLECTOR_SWEEP_INTERVAL);
        loop {
            tokio::select! {
                now = sweeper.tick() => {
                    self.sweep_stale_flows(now.into_std()).await;
                },
                maybe_flow = self.rx.recv() => {
                    match maybe_flow {
                        Some(flow) => self.collect_flow(flow),
                        None => {
                            log::warn!("FlowCollector channel closed");
                            break;
                        },
                    }
                }
                _ = shutdown.cancelled() => {
                    log::info!("FlowCollector shutting down");
                    break;
                }
                else => break,
            }
        }
    }
}

struct EventBufferReaderTask {
    fd: AsyncFd<PerfEventArrayBuffer<MapData>>,
    tracker: FlowCollector,
}

impl EventBufferReaderTask {
    async fn run(&mut self, shutdown: ShutdownGuard) {
        let buf_sz = size_of::<Flow>();
        let mut buffers = std::iter::repeat_with(|| BytesMut::with_capacity(buf_sz))
            .take(EVENTS_READ_BUF_SIZE)
            .collect::<Vec<_>>();

        loop {
            select! {
                maybe_guard = self.fd.readable_mut() => {
                    match maybe_guard {
                        Ok(mut guard) => {
                            loop {
                                let Events { read, lost } = guard
                                    .get_inner_mut()
                                    .read_events(&mut buffers)
                                    .expect("Failed to read events from eBPF map");

                                if lost > 0 {
                                    log::warn!(
                                        "Lost {} events from eBPF events map due to ring buffer overwrites",
                                        lost
                                    );
                                }

                                for buf in buffers.iter().take(read) {
                                    let flow = unsafe { (buf.as_ptr() as *const Flow).read_unaligned() };
                                    self.tracker
                                        .collect_flow(flow)
                                        .inspect_err(|err| log::error!("Failed to collect flow {:?}", err))
                                        .ok();
                                }

                                if read != buffers.len() {
                                    break;
                                }
                            }
                            guard.clear_ready();
                        },
                        Err(err) => {
                            log::error!("Could not read eBPF map buffer: {err}");
                        },
                    }
                },
                _ = shutdown.cancelled() => {
                    log::info!("eBPF event buffer reader shutting down");
                    break;
                },
            }
        }
    }
}
