use anyhow::{Result, anyhow};
use chrono::Utc;
use flate2::read::GzDecoder;
use futures_util::stream::StreamExt;
use std::io::Read;
use std::{net::Ipv4Addr, path::Path, sync::Arc, time::Duration};
use tokio::{select, sync::RwLock, time};
use tokio_graceful::ShutdownGuard;
use tokio_util::task::AbortOnDropHandle;

use serde::Deserialize;

use crate::events::IpAsMetadata;

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct IpAsnDbConfig {
    pub data_dir: String,
    pub refresh_interval: Duration,
    pub download_url: String,
}

impl Default for IpAsnDbConfig {
    fn default() -> Self {
        IpAsnDbConfig {
            data_dir: "/var/db/narcd".to_owned(),
            refresh_interval: Duration::from_hours(4),
            download_url: "https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz".to_owned(),
        }
    }
}

#[derive(PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
struct IpAsnRecord {
    range_start: u32,
    range_end: u32,
    as_number: u32,
    country_code: String,
    as_description: String,
}

pub struct IpAsnDb {
    db: Arc<RwLock<Vec<IpAsnRecord>>>,
    _refresh_task: AbortOnDropHandle<()>,
}

impl IpAsnDb {
    pub async fn new(config: IpAsnDbConfig, shutdown: ShutdownGuard) -> Result<Self> {
        let db = Arc::new(RwLock::new(Vec::new()));
        let mut task = PeriodicRefreshTask {
            db: db.clone(),
            config,
        };
        let handle = shutdown.into_spawn_task_fn(|guard| async move { task.run(guard).await });

        Ok(Self {
            db,
            _refresh_task: AbortOnDropHandle::new(handle),
        })
    }

    pub async fn lookup(&self, ip: Ipv4Addr) -> Option<IpAsMetadata> {
        let db = self.db.read().await;
        let ip_n = ip.to_bits();

        let record = match db.binary_search_by_key(&ip_n, |rec| rec.range_start) {
            Ok(index) => db.get(index),
            Err(index) => Some(index)
                .filter(|index| *index > 0)
                .and_then(|index| db.get(index - 1))
                .filter(|rec| rec.range_start <= ip_n && ip_n <= rec.range_end),
        };

        record.map(|rec| IpAsMetadata {
            num: rec.as_number,
            desc: rec.as_description.clone(),
            country: rec.country_code.clone(),
        })
    }
}

struct PeriodicRefreshTask {
    db: Arc<RwLock<Vec<IpAsnRecord>>>,
    config: IpAsnDbConfig,
}

impl PeriodicRefreshTask {
    async fn run(&mut self, shutdown: ShutdownGuard) {
        let mut refresh = time::interval(Duration::from_mins(15));
        loop {
            select! {
                _ = refresh.tick() => {
                    match self.refresh_ipasn_db().await {
                        Ok(new_db) => *self.db.write().await = new_db,
                        Err(e) => log::error!("Failed to refresh IP-to-ASN database: {}", e),
                    }
                }
                _ = shutdown.cancelled() => {
                    log::info!("ipasn refresh task shutting down");
                    break;
                },
            }
        }
    }

    async fn load_from_cache(
        &self,
        cache_path: &Path,
        timestamp_path: &Path,
    ) -> Result<Option<Vec<IpAsnRecord>>> {
        if !cache_path.exists() || !timestamp_path.exists() {
            return Ok(None);
        }

        let timestamp_str = tokio::fs::read_to_string(timestamp_path).await?;
        let cached_time = timestamp_str.parse::<i64>()?;

        let now = Utc::now().timestamp();
        let age = (now - cached_time).max(0) as u64;

        if age >= self.config.refresh_interval.as_secs() {
            log::info!("Disk cache is stale (age: {}s), will re-download", age);
            return Ok(None);
        }

        log::info!("ipasn database is fresh");
        let bytes = tokio::fs::read(cache_path).await?;
        let records = bincode::deserialize::<Vec<IpAsnRecord>>(&bytes)?;

        Ok(Some(records))
    }

    async fn download_ipasn_tsv(&self) -> Result<String> {
        let download_url = &self.config.download_url;

        log::info!("Downloading IP-to-ASN database from {}", download_url);
        let response = reqwest::get(download_url).await?;
        let bytes = response.bytes().await?;

        let mut decoder = GzDecoder::new(bytes.as_ref());
        let mut content = String::new();
        decoder.read_to_string(&mut content)?;

        Ok(content)
    }

    async fn build_ipasn_db(&self, content: &str) -> Result<Vec<IpAsnRecord>> {
        let mut records = Vec::new();

        let mut rdr = csv_async::AsyncReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .create_deserializer(content.as_bytes());

        let mut raw_records = rdr.deserialize::<IpAsnRecord>();

        while let Some(result) = raw_records.next().await {
            let record = result.map_err(|e| anyhow!("Failed to parse TSV record: {}", e))?;

            if record.range_start > record.range_end {
                return Err(anyhow!(
                    "Invalid range: {} > {}",
                    record.range_start,
                    record.range_end
                ));
            }

            records.push(record);
        }

        records.sort_by_key(|r| r.range_start);

        log::info!("Parsed {} IP-to-ASN records", records.len());

        Ok(records)
    }

    async fn write_ipasn_db(
        &self,
        cache_path: &Path,
        timestamp_path: &Path,
        records: &[IpAsnRecord],
    ) -> Result<()> {
        let temp_cache = cache_path.with_extension("tmp");
        let encoded = bincode::serialize(records)?;
        tokio::fs::write(&temp_cache, encoded).await?;

        let temp_timestamp = timestamp_path.with_extension("tmp");
        let timestamp = Utc::now().timestamp();
        tokio::fs::write(&temp_timestamp, timestamp.to_string()).await?;

        tokio::fs::rename(&temp_cache, cache_path).await?;
        tokio::fs::rename(&temp_timestamp, timestamp_path).await?;
        log::info!("Saved IP-to-ASN database to {}", cache_path.display());

        Ok(())
    }

    async fn refresh_ipasn_db(&self) -> Result<Vec<IpAsnRecord>> {
        let cache_path = Path::new(&self.config.data_dir).join("ip2asn-v4.db");
        let timestamp_path = Path::new(&self.config.data_dir).join("ip2asn-v4.db.meta");

        match self.load_from_cache(&cache_path, &timestamp_path).await {
            Ok(Some(records)) => return Ok(records),
            Ok(None) => {
                // Cache is stale or doesn't exist, continue to download
            }
            Err(e) => {
                log::warn!(
                    "Failed to load IP-ASN DB from disk, will re-download: {}",
                    e
                );
            }
        }

        tokio::fs::create_dir_all(&self.config.data_dir).await?;
        let content = self.download_ipasn_tsv().await?;
        let records = self.build_ipasn_db(&content).await?;
        self.write_ipasn_db(&cache_path, &timestamp_path, &records)
            .await?;

        Ok(records)
    }
}
