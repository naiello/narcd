use std::net::IpAddr;
use serde::Serialize;

#[derive(PartialEq, Eq, Serialize, Debug)]
#[serde(tag = "method")]
pub enum SshAuthMethod {
    None,
    Password { password: String },
    PublicKey { fingerprint: String, algorithm: String, comment: String },
}

#[derive(PartialEq, Eq, Serialize, Debug)]
#[serde(tag = "type")]
pub enum Event {
    SshLogin {
        username: String,
        auth: SshAuthMethod,
        src_ip: Option<IpAddr>,
        src_port: Option<u16>,
    },
}

