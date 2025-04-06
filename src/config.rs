use serde::Deserialize;
use crate::listeners::ListenersConfig;
use crate::logger::LoggingConfig;

#[derive(Default, Deserialize)]
pub struct Config {
    pub listeners: ListenersConfig,
    pub log: LoggingConfig,
}

