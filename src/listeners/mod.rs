use serde::Deserialize;

pub mod ssh;

use crate::listeners::ssh::SshConfig;

#[derive(Default, Deserialize)]
pub struct ListenersConfig {
    pub ssh: SshConfig,
}
