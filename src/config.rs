use crate::listeners::ListenersConfig;
use crate::logger::LoggingConfig;
use serde::Deserialize;

#[derive(Default, Deserialize)]
pub struct Config {
    pub listeners: ListenersConfig,
    pub log: LoggingConfig,
}
