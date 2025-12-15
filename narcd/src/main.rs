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
    let logger = FileLogger::new(&config.log.dir).await?;
    tokio::spawn(async move {
        start_ebpf().await.inspect_err(|err| log::error!("Failed to start eBPF: {}", err))
    });
    start_server(&config.listeners.ssh, &metadata, logger).await?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    Ok(())
}
