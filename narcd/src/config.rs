use crate::ipasn::IpAsnDbConfig;
use crate::listeners::ListenersConfig;
use crate::logger::LoggingConfig;
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listeners: ListenersConfig,
    pub log: LoggingConfig,
    pub ipasn: IpAsnDbConfig,
}
