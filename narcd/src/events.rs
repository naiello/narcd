use chrono::{DateTime, Utc};
use narcd_common::FlowType;
use serde::{Serialize, Serializer};
use std::net::IpAddr;

use crate::{metadata::Metadata, passwdstats::PasswordStatistics, util::Shared};

#[derive(Serialize, Debug)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum SshAuthMethod {
    None,
    Password {
        password: String,
        stats: PasswordStatistics,
    },
    PublicKey {
        key_fingerprint: String,
        key_algorithm: String,
        key_comment: String,
    },
}

#[derive(Serialize, Debug)]
pub struct SshLogin {
    #[serde(serialize_with = "serialize_ts")]
    pub ts: DateTime<Utc>,
    pub username: String,
    pub auth: SshAuthMethod,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip_as: Option<IpAsMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip_geo: Option<IpGeoMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_hostname: Option<String>,
    pub metadata: Metadata,
}

impl Shared for SshLogin {}

#[derive(PartialEq, Serialize, Debug)]
pub struct PortScan {
    #[serde(serialize_with = "serialize_ts")]
    pub ts: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_ports: Vec<u16>,
    pub dst_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip_as: Option<IpAsMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip_geo: Option<IpGeoMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_hostname: Option<String>,
    pub metadata: Metadata,
    pub scan_type: FlowType,
}

impl Shared for PortScan {}

#[derive(PartialEq, Eq, Serialize, Debug)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum HttpAuthMethod {
    None,
    Basic { username: String, password: String },
    Other { value: String },
}

#[derive(PartialEq, Serialize, Debug)]
pub struct HttpRequest {
    #[serde(serialize_with = "serialize_ts")]
    pub ts: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,

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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip_as: Option<IpAsMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip_geo: Option<IpGeoMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_hostname: Option<String>,
    pub metadata: Metadata,
}

impl Shared for HttpRequest {}

#[derive(PartialEq, Eq, Serialize, Debug)]
pub struct IpAsMetadata {
    pub num: u32,
    pub desc: String,
    pub country: String,
}

#[derive(PartialEq, Serialize, Debug, Clone)]
pub struct IpGeoMetadata {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region_code: Option<String>,
    pub region_name: Option<String>,
    pub city: Option<String>,
    pub postal_code: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

fn serialize_ts<S: Serializer>(v: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&v.format("%Y-%m-%dT%H:%M:%S%.3fZ"))
}
