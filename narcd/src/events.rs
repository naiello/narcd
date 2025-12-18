use chrono::{DateTime, Utc};
use narcd_common::FlowType;
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
        key_fingerprint: String,
        key_algorithm: String,
        key_comment: String,
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

#[derive(PartialEq, Eq, Serialize, Debug)]
pub struct PortScan {
    #[serde(serialize_with = "serialize_ts")]
    pub ts: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_ports: Vec<u16>,
    pub dst_ports: Vec<u16>,
    pub metadata: Metadata,
    pub scan_type: FlowType,
}

fn serialize_ts<S: Serializer>(v: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&v.format("%Y-%m-%dT%H:%M:%S%.3fZ"))
}
