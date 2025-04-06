use narcd::listeners::ssh::start_server;
use anyhow::Result;
use narcd::logger::FileLogger;
use narcd::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init_timed();
    let config: Config = Default::default();
    let logger = FileLogger::new(&config.log.filename).await?;
    start_server(&config.listeners.ssh, logger).await?;
    Ok(())
}
