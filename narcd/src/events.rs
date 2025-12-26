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

#[derive(PartialEq, Eq, Serialize, Debug)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum HttpAuthMethod {
    None,
    Basic { username: String, password: String },
    Other { value: String },
}

#[derive(PartialEq, Eq, Serialize, Debug)]
pub struct HttpRequest {
    #[serde(serialize_with = "serialize_ts")]
    pub ts: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub src_ip: IpAddr,
    pub src_port: u16,

    pub auth: HttpAuthMethod,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub body_size: usize,
    pub body_truncated: bool,

    pub metadata: Metadata,
}

fn serialize_ts<S: Serializer>(v: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&v.format("%Y-%m-%dT%H:%M:%S%.3fZ"))
}
