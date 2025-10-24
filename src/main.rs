use anyhow::Result;
use narcd::config::Config;
use narcd::listeners::ssh::start_server;
use narcd::logger::FileLogger;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init_timed();

    let config: Config = Default::default();
    let logger = FileLogger::new(&config.log.dir).await?;
    start_server(&config.listeners.ssh, logger).await?;

    Ok(())
}
