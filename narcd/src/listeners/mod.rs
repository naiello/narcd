use serde::Deserialize;

pub mod http;
pub mod ssh;

use crate::listeners::http::HttpConfig;
use crate::listeners::ssh::SshConfig;

#[derive(Default, Deserialize)]
pub struct ListenersConfig {
    pub ssh: SshConfig,
    pub http: HttpConfig,
}
