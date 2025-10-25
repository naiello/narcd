use anyhow::Result;
use aws_config::imds;
use narcd::config::Config;
use narcd::listeners::ssh::start_server;
use narcd::logger::FileLogger;
use narcd::metadata::resolve_metadata;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init_timed();

    let imds = imds::Client::builder().build();
    let metadata = resolve_metadata(&imds).await?;
    let config: Config = Default::default();
    let logger = FileLogger::new(&config.log.dir).await?;
    start_server(&config.listeners.ssh, &metadata, logger).await?;

    Ok(())
}
