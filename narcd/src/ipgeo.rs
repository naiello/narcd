use anyhow::{Context, Result, anyhow};
use aws_config::SdkConfig;
use aws_sdk_ssm::Client as SsmClient;
use chrono::Utc;
use flate2::read::GzDecoder;
use maxminddb::Reader;
use std::ffi::OsStr;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use serde::Deserialize;

use crate::events::IpGeoMetadata;

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct IpGeoDbConfig {
    pub data_dir: String,
    pub refresh_interval: Duration,
    pub download_url: String,
    pub api_key_parameter: String,
}

impl Default for IpGeoDbConfig {
    fn default() -> Self {
        IpGeoDbConfig {
            data_dir: "/var/db/narcd".to_owned(),
            refresh_interval: Duration::from_hours(4),
            download_url:
                "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
                    .to_owned(),
            api_key_parameter: "/narcd/maxmind-api-key".to_owned(),
        }
    }
}

pub struct IpGeoDb {
    reader: Arc<RwLock<Reader<Vec<u8>>>>,
}

impl IpGeoDb {
    pub async fn new(config: IpGeoDbConfig, sdk_config: Arc<SdkConfig>) -> Result<Self> {
        let mmdb_data = refresh_ipgeo_db(&config, sdk_config.as_ref()).await?;
        let reader = Reader::from_source(mmdb_data)
            .context("Failed to create MaxMind reader from database")?;
        let reader = Arc::new(RwLock::new(reader));

        tokio::spawn(periodic_refresh_ipgeo_db(
            reader.clone(),
            config.clone(),
            sdk_config,
        ));

        Ok(Self { reader })
    }

    pub async fn lookup(&self, ip: Ipv4Addr) -> Option<IpGeoMetadata> {
        let reader = self.reader.read().await;

        let city: maxminddb::geoip2::City = reader.lookup(IpAddr::V4(ip)).ok()?;

        Some(IpGeoMetadata {
            country_code: city
                .country
                .as_ref()
                .and_then(|c| c.iso_code)
                .map(|s| s.to_string()),
            country_name: city
                .country
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en"))
                .map(|s| s.to_string()),
            region_code: city
                .subdivisions
                .as_ref()
                .and_then(|subs| subs.first())
                .and_then(|s| s.iso_code)
                .map(|s| s.to_string()),
            region_name: city
                .subdivisions
                .as_ref()
                .and_then(|subs| subs.first())
                .and_then(|s| s.names.as_ref())
                .and_then(|n| n.get("en"))
                .map(|s| s.to_string()),
            city: city
                .city
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en"))
                .map(|s| s.to_string()),
            postal_code: city
                .postal
                .as_ref()
                .and_then(|p| p.code)
                .map(|s| s.to_string()),
            latitude: city.location.as_ref().and_then(|l| l.latitude),
            longitude: city.location.as_ref().and_then(|l| l.longitude),
            timezone: city
                .location
                .as_ref()
                .and_then(|l| l.time_zone)
                .map(|s| s.to_string()),
        })
    }
}

async fn periodic_refresh_ipgeo_db(
    reader: Arc<RwLock<Reader<Vec<u8>>>>,
    config: IpGeoDbConfig,
    sdk_config: Arc<SdkConfig>,
) -> ! {
    loop {
        let new_db = refresh_ipgeo_db(&config, sdk_config.as_ref())
            .await
            .and_then(|new_db| {
                Reader::from_source(new_db).context("Failed to build MaxMind DB reader")
            });

        match new_db {
            Ok(new_db) => *reader.write().await = new_db,
            Err(e) => log::error!("Failed to refresh MaxMind database: {}", e),
        }

        tokio::time::sleep(Duration::from_mins(15)).await;
    }
}

async fn load_from_cache(
    cache_path: &Path,
    timestamp_path: &Path,
    refresh_interval: Duration,
) -> Result<Option<Vec<u8>>> {
    if !cache_path.exists() || !timestamp_path.exists() {
        return Ok(None);
    }

    let timestamp_str = tokio::fs::read_to_string(timestamp_path).await?;
    let cached_time = timestamp_str.parse::<i64>()?;

    let now = Utc::now().timestamp();
    let age = (now - cached_time).max(0) as u64;

    if age >= refresh_interval.as_secs() {
        log::info!(
            "MaxMind disk cache is stale (age: {}s), will re-download",
            age
        );
        return Ok(None);
    }

    let bytes = tokio::fs::read(cache_path).await?;
    log::info!("Loaded MaxMind database from cache");

    Ok(Some(bytes))
}

async fn fetch_api_key_from_parameter_store(
    sdk_config: &SdkConfig,
    parameter_name: &str,
) -> Result<String> {
    let ssm_client = SsmClient::new(sdk_config);

    let response = ssm_client
        .get_parameter()
        .name(parameter_name)
        .with_decryption(true)
        .send()
        .await
        .context(format!(
            "Failed to fetch API key from Parameter Store: {}",
            parameter_name
        ))?;

    let api_key = response
        .parameter()
        .ok_or_else(|| anyhow!("Parameter not found: {}", parameter_name))?
        .value()
        .ok_or_else(|| anyhow!("Parameter has no value: {}", parameter_name))?
        .to_string();

    Ok(api_key)
}

async fn download_maxmind_db(download_url: &str, api_key: &str) -> Result<Vec<u8>> {
    log::info!("Downloading MaxMind database from MaxMind");

    let client = reqwest::Client::new();
    let (user, pass) = api_key
        .split_once(":")
        .context("API key is not in a valid format (expected <account>:<license-key>)")?;
    let response = client
        .get(download_url)
        .basic_auth(user, Some(pass))
        .send()
        .await
        .context("Failed to download MaxMind database")?
        .bytes()
        .await
        .context("Failed to read MaxMind download response")?;

    log::info!("Extracting .mmdb file from tar.gz archive");

    let tar_decoder = GzDecoder::new(response.as_ref());
    let mut archive = tar::Archive::new(tar_decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if path.extension() == Some(OsStr::new("mmdb")) {
            log::info!("Found .mmdb file in archive: {}", path.display());
            let mut mmdb_bytes = Vec::new();
            entry.read_to_end(&mut mmdb_bytes)?;
            log::info!("Extracted {} bytes from .mmdb file", mmdb_bytes.len());
            return Ok(mmdb_bytes);
        }
    }

    Err(anyhow!("No .mmdb file found in tar.gz archive"))
}

async fn write_maxmind_db(
    cache_path: &Path,
    timestamp_path: &Path,
    mmdb_data: &[u8],
) -> Result<()> {
    let temp_cache = cache_path.with_extension("tmp");
    tokio::fs::write(&temp_cache, mmdb_data).await?;

    let temp_timestamp = timestamp_path.with_extension("tmp");
    let timestamp = Utc::now().timestamp();
    tokio::fs::write(&temp_timestamp, timestamp.to_string()).await?;

    tokio::fs::rename(&temp_cache, cache_path).await?;
    tokio::fs::rename(&temp_timestamp, timestamp_path).await?;

    log::info!("Saved MaxMind database to {}", cache_path.display());

    Ok(())
}

async fn refresh_ipgeo_db(config: &IpGeoDbConfig, sdk_config: &SdkConfig) -> Result<Vec<u8>> {
    let cache_path = Path::new(&config.data_dir).join("geolite2-city.mmdb");
    let timestamp_path = Path::new(&config.data_dir).join("geolite2-city.mmdb.meta");

    match load_from_cache(&cache_path, &timestamp_path, config.refresh_interval).await {
        Ok(Some(data)) => return Ok(data),
        Ok(None) => {
            // Cache is stale or doesn't exist, continue to download
        }
        Err(e) => {
            log::warn!(
                "Failed to load MaxMind DB from disk, will re-download: {}",
                e
            );
        }
    }

    tokio::fs::create_dir_all(&config.data_dir).await?;

    let api_key = fetch_api_key_from_parameter_store(sdk_config, &config.api_key_parameter).await?;

    let mmdb_data = download_maxmind_db(&config.download_url, &api_key).await?;
    write_maxmind_db(&cache_path, &timestamp_path, &mmdb_data).await?;

    Ok(mmdb_data)
}
