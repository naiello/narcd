use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::IpAddr;

#[derive(PartialEq, Eq, Serialize, Debug)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SshAuthMethod {
    None,
    Password {
        password: String,
    },
    PublicKey {
        fingerprint: String,
        algorithm: String,
        comment: String,
    },
}

#[derive(PartialEq, Eq, Serialize, Debug)]
pub struct SshLogin {
    pub ts: DateTime<Utc>,
    pub username: String,
    pub auth: SshAuthMethod,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
}
