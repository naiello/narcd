use anyhow::{Context, Result};
use aws_config::imds;
use narcd::config::Config;
use narcd::ebpf::EbpfListener;
use narcd::ipasn::IpAsnDb;
use narcd::ipgeo::IpGeoDb;
use narcd::listeners::http::HttpServer;
use narcd::listeners::ssh::SshServer;
use narcd::logger::FileLogger;
use narcd::metadata::resolve_metadata;
use narcd_common::{PacketDisposition, PacketSource};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio_graceful::Shutdown;

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        unsafe { env::set_var("RUST_LOG", "info") };
    }
    pretty_env_logger::init_timed();

    let shutdown = Shutdown::default();
    let config = config::Config::builder()
        .add_source(config::File::with_name("/etc/narcd/narcd").required(false))
        .add_source(config::File::with_name("narcd").required(false))
        .build()?
        .try_deserialize::<Config>()?;
    let imds = imds::Client::builder().build();
    let metadata = Arc::new(resolve_metadata(&imds).await?);
    log::info!("Local IP is: {}", metadata.ip);

    let sdk_config =
        Arc::new(aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await);

    let ipasn_db = Arc::new(IpAsnDb::new(config.ipasn, shutdown.guard()).await?);
    let ipgeo_db = Arc::new(IpGeoDb::new(config.ipgeo, sdk_config, shutdown.guard()).await?);

    // TODO: Move this into config.
    // Don't log wireguard traffic from the management IP
    let mut pktdisp = HashMap::new();
    pktdisp.insert(
        PacketSource {
            dst_port: 33666,
            proto: 17, // UDP
        },
        PacketDisposition::Ignore,
    );

    let scan_logger = FileLogger::new(&config.log.dir, "scan.log", shutdown.guard()).await?;
    let _ebpf = EbpfListener::start(
        metadata.clone(),
        scan_logger,
        pktdisp,
        ipasn_db.clone(),
        ipgeo_db.clone(),
        shutdown.guard(),
    )
    .await
    .context("Failed to init eBPF")?;

    let ssh_logger = FileLogger::new(&config.log.dir, "ssh.log", shutdown.guard()).await?;
    let _ssh = SshServer::start(
        &config.listeners.ssh,
        metadata.clone(),
        ssh_logger,
        ipasn_db.clone(),
        ipgeo_db.clone(),
        shutdown.guard(),
    )
    .await
    .context("Failed to start SSH server")?;

    let http_logger = FileLogger::new(&config.log.dir, "http.log", shutdown.guard()).await?;
    let _http = HttpServer::start(
        &config.listeners.http,
        metadata.clone(),
        http_logger,
        ipasn_db.clone(),
        ipgeo_db.clone(),
        shutdown.guard(),
    )
    .await
    .context("Failed to start HTTP server")?;

    shutdown
        .shutdown_with_limit(std::time::Duration::from_mins(2))
        .await
        .context("Failure while running graceful shutdown")?;

    log::info!("Shutdown complete");

    Ok(())
}
