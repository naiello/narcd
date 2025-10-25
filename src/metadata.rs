use anyhow::Result;
use aws_config::imds;
use std::net::IpAddr;

use local_ip_address::local_ip;
use serde::Serialize;

#[derive(PartialEq, Eq, Debug, Serialize, Clone)]
pub struct Metadata {
    pub ip: IpAddr,
    pub aws: Option<AwsMetadata>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Clone)]
pub struct AwsMetadata {
    pub instance_id: String,
    pub region: String,
    pub azid: String,
}

pub async fn resolve_metadata(imds: &imds::Client) -> Result<Metadata> {
    resolve_metadata_from_aws(imds)
        .await
        .or_else(|_| resolve_metadata_from_local())
}

pub async fn resolve_metadata_from_aws(imds: &imds::Client) -> Result<Metadata> {
    let instance_id = imds.get("/latest/meta-data/instance-id").await?.into();
    let ip = imds
        .get("/latest/meta-data/public-ipv4")
        .await?
        .as_ref()
        .parse()?;
    let region = imds.get("/latest/meta-data/placement/region").await?.into();
    let azid = imds
        .get("/latest/meta-data/placement/availability-zone-id")
        .await?
        .into();

    log::info!("Resolving metadata from IMDS");
    let aws = Some(AwsMetadata {
        instance_id,
        region,
        azid,
    });
    let metadata = Metadata { ip, aws };
    Ok(metadata)
}

pub fn resolve_metadata_from_local() -> Result<Metadata> {
    log::info!("Resolving metadata from local sources");
    Ok(Metadata {
        ip: local_ip()?,
        aws: None,
    })
}
