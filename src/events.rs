use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use std::net::IpAddr;

use crate::metadata::Metadata;

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
    #[serde(serialize_with = "serialize_ts")]
    pub ts: DateTime<Utc>,
    pub username: String,
    pub auth: SshAuthMethod,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub metadata: Metadata,
}

fn serialize_ts<S: Serializer>(v: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&v.format("%Y-%m-%dT%H:%M:%S%.3fZ"))
}
