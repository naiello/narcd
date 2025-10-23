use anyhow::Result;
use narcd::config::Config;
use narcd::listeners::ssh::start_server;
use narcd::logger::FileLogger;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();
    let config: Config = Default::default();
    let logger = FileLogger::new(&config.log.filename).await?;
    start_server(&config.listeners.ssh, logger).await?;
    Ok(())
}
