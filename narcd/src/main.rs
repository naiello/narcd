use anyhow::Result;
use aws_config::imds;
use narcd::config::Config;
use narcd::ebpf::start_ebpf;
use narcd::listeners::ssh::start_server;
use narcd::logger::FileLogger;
use narcd::metadata::resolve_metadata;
use std::env;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        unsafe { env::set_var("RUST_LOG", "info") };
    }
    pretty_env_logger::init_timed();

    let imds = imds::Client::builder().build();
    let metadata = resolve_metadata(&imds).await?;
    let config: Config = Default::default();

    let scan_logger = FileLogger::new(&config.log.dir, "scan.log").await?;
    tokio::spawn(async move {
        start_ebpf(scan_logger)
            .await
            .inspect_err(|err| log::error!("Failed to start eBPF: {:?}", err))
    });

    let ssh_logger = FileLogger::new(&config.log.dir, "ssh.log").await?;
    tokio::spawn(async move {
        start_server(&config.listeners.ssh, &metadata, ssh_logger)
            .await
            .inspect_err(|err| log::error!("Failed to start ssh handler: {:?}", err))
    });

    signal::ctrl_c().await?;
    log::info!("Exiting due to SIGTERM");

    Ok(())
}
