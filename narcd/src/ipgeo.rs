use anyhow::{Context, Result, anyhow, bail};
use aws_config::SdkConfig;
use aws_sdk_ssm::Client as SsmClient;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use maxminddb::{Mmap, Reader};
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::{select, sync::RwLock, time};
use tokio_graceful::ShutdownGuard;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

use serde::Deserialize;

use crate::events::IpGeoMetadata;

#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct IpGeoDbConfig {
    pub data_dir: String,
    pub download_url: String,
    pub api_key_parameter: String,
}

impl IpGeoDbConfig {
    pub fn cache_path(&self) -> PathBuf {
        PathBuf::new()
            .join(&self.data_dir)
            .join("geolite2-city.mmdb")
    }

    pub fn meta_path(&self) -> PathBuf {
        PathBuf::new()
            .join(&self.data_dir)
            .join("geolite2-city.mmdb.meta")
    }

    pub fn tmp_path(&self) -> PathBuf {
        PathBuf::new().join(&self.data_dir).join("tmp")
    }
}

impl Default for IpGeoDbConfig {
    fn default() -> Self {
        IpGeoDbConfig {
            data_dir: "/var/db/narcd".to_owned(),
            download_url:
                "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
                    .to_owned(),
            api_key_parameter: "/narcd/maxmind-api-key".to_owned(),
        }
    }
}

pub struct IpGeoDb {
    reader: Arc<RwLock<Reader<Mmap>>>,
    _refresh_task: AbortOnDropHandle<()>,
}

struct DatabasePaths {
    db: PathBuf,
    meta: PathBuf,
}

impl IpGeoDb {
    pub async fn new(
        config: IpGeoDbConfig,
        sdk_config: Arc<SdkConfig>,
        shutdown: ShutdownGuard,
    ) -> Result<Self> {
        let config = Arc::new(config);
        let mut task = IpGeoRefreshTask {
            config: config.clone(),
            sdk_config,
            is_bootstrapped: false,
        };
        let reader = Arc::new(RwLock::new(
            task.bootstrap()
                .await
                .context("Failed to bootstrap ipgeo database")?,
        ));

        let mut periodic_task = IpGeoPeriodicRefreshTask {
            task,
            reader: reader.clone(),
        };
        let handle =
            shutdown.into_spawn_task_fn(|guard| async move { periodic_task.run(guard).await });

        Ok(Self {
            reader,
            _refresh_task: AbortOnDropHandle::new(handle),
        })
    }

    pub async fn lookup(&self, ip: Ipv4Addr) -> Option<IpGeoMetadata> {
        let reader = self.reader.read().await;

        let city: maxminddb::geoip2::City = reader
            .lookup(IpAddr::V4(ip))
            .inspect_err(|err| {
                if !matches!(err, maxminddb::MaxMindDBError::AddressNotFoundError(_)) {
                    log::warn!("failed to look up {ip} in maxmind: {err}")
                }
            })
            .ok()?;

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

struct IpGeoPeriodicRefreshTask {
    reader: Arc<RwLock<Reader<Mmap>>>,
    task: IpGeoRefreshTask,
}

struct IpGeoRefreshTask {
    config: Arc<IpGeoDbConfig>,
    sdk_config: Arc<SdkConfig>,
    is_bootstrapped: bool,
}

impl IpGeoPeriodicRefreshTask {
    async fn run(&mut self, shutdown: ShutdownGuard) -> () {
        let mut refresh = time::interval(Duration::from_hours(1));
        loop {
            select! {
                _ = refresh.tick() => {
                    match self.task.reload(self.reader.clone()).await {
                        Ok(_) => log::info!("Database reload complete"),
                        Err(e) => log::error!("Failed to refresh MaxMind database: {}", e),
                    }
                },
                _ = shutdown.cancelled() => {
                    log::info!("ipgeo refresh task stopping");
                    break;
                },
            }
        }
    }
}

impl IpGeoRefreshTask {
    async fn bootstrap(&mut self) -> Result<Reader<Mmap>> {
        if self.is_bootstrapped {
            // Defense against accidentally calling multuple times and mmap'ing the same file in
            // multiple places, which would be unsafe when we perform a reload.
            bail!("bootstrap called multiple times!");
        }

        let db = &self.config.cache_path();
        let meta = &self.config.meta_path();
        let paths = &self
            .refresh_ipgeo_db()
            .await
            .context("Failed to bootstrap ipgeo database")?;

        if &paths.db != db {
            tokio::fs::rename(&paths.db, db).await?;
        }
        if &paths.meta != meta {
            tokio::fs::rename(&paths.meta, meta).await?;
        }

        let reader = Reader::open_mmap(db).context("Failed to mmap MaxMind DB")?;

        self.is_bootstrapped = true;
        Ok(reader)
    }

    async fn reload(&mut self, reader: Arc<RwLock<Reader<Mmap>>>) -> Result<()> {
        if !self.is_bootstrapped {
            bail!("bootstrap was never called!");
        }

        let db = &self.config.cache_path();
        let meta = &self.config.meta_path();
        let paths = &self
            .refresh_ipgeo_db()
            .await
            .context("Failed to refresh DB")?;

        // Safety: write lock must be held to ensure no one is reading from any previously
        // mmap'd versions of this file.
        {
            let mut write = reader.write().await;
            if &paths.db != db {
                tokio::fs::rename(&paths.db, db).await?;
            }
            if &paths.meta != meta {
                tokio::fs::rename(&paths.meta, meta).await?;
            }
            let reader = Reader::open_mmap(db).context("Failed to mmap MaxMind DB")?;
            *write = reader;
        }

        Ok(())
    }

    async fn refresh_ipgeo_db(&mut self) -> Result<DatabasePaths> {
        if self.is_current_db_fresh().await? {
            log::info!("MaxMind data is fresh");
            let paths = DatabasePaths {
                db: self.config.cache_path(),
                meta: self.config.meta_path(),
            };
            return Ok(paths);
        }

        log::info!("MaxMind cache is stale or unavailable, reloading");
        let api_key = self.fetch_api_key_from_parameter_store().await?;
        self.download_maxmind_db(&api_key).await
    }

    async fn is_current_db_fresh(&self) -> Result<bool> {
        let cache_path = self.config.cache_path();
        let meta_path = self.config.meta_path();

        if !cache_path.exists() || !meta_path.exists() {
            log::info!("MaxMind cache does not exist, bootstrapping");
            tokio::fs::create_dir_all(&self.config.data_dir).await?;
            return Ok(false);
        }

        let latest_ts = self.get_latest_available_db_timestamp().await?;
        let current_ts = self.get_current_db_timestamp().await?;
        let is_fresh = latest_ts <= current_ts;

        if !is_fresh {
            log::info!("Newer MaxMind database available. Ours: {latest_ts}, theirs: {latest_ts}")
        }
        Ok(is_fresh)
    }

    async fn get_latest_available_db_timestamp(&self) -> Result<DateTime<Utc>> {
        let api_key = self.fetch_api_key_from_parameter_store().await?;
        let client = reqwest::Client::new();
        let (user, pass) = api_key
            .split_once(":")
            .context("API key is not in a valid format (expected <account>:<license-key>)")?;

        client
            .head(&self.config.download_url)
            .basic_auth(user, Some(pass))
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .context("Failed to check MaxMind database headers")?
            .headers()
            .get("last-modified")
            .ok_or_else(|| anyhow!("MaxMind did not provide a last-modified date"))
            .and_then(|hdr| hdr.to_str().context("last-modified was not a string"))
            .and_then(|ts| DateTime::parse_from_rfc2822(ts).context("invalid last-modified date"))
            .map(|ts| ts.to_utc())
    }

    async fn get_current_db_timestamp(&self) -> Result<DateTime<Utc>> {
        tokio::fs::read_to_string(self.config.meta_path())
            .await
            .context("Failed to read meta file")
            .and_then(|ts| {
                DateTime::parse_from_rfc3339(ts.trim()).context("Failed to parse meta file")
            })
            .map(|ts| ts.to_utc())
    }

    async fn fetch_api_key_from_parameter_store(&self) -> Result<String> {
        let ssm_client = SsmClient::new(self.sdk_config.as_ref());

        let parameter_name = &self.config.api_key_parameter;
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

    async fn download_maxmind_db(&self, api_key: &str) -> Result<DatabasePaths> {
        log::info!("Downloading MaxMind database");

        let uuid = Uuid::new_v4().to_string();
        let new_db_path = self.config.tmp_path().join(&uuid);
        let new_meta_path = self.config.tmp_path().join(&uuid).join("meta");
        tokio::fs::create_dir_all(new_db_path.clone()).await?;
        tokio::fs::write(&new_meta_path, "foobar").await?;

        let client = reqwest::Client::new();
        let (user, pass) = api_key
            .split_once(":")
            .context("API key is not in a valid format (expected <account>:<license-key>)")?;
        let request = client
            .get(&self.config.download_url)
            .basic_auth(user, Some(pass))
            .send()
            .await
            .context("Failed to download MaxMind database")?;

        let mtime = request
            .headers()
            .get("last-modified")
            .ok_or_else(|| anyhow!("maxmind did not provide last-modified"))
            .and_then(|hdr| hdr.to_str().context("last-modified was not a string"))
            .and_then(|ts| {
                DateTime::parse_from_rfc2822(ts).context("could not parse last-modified")
            })
            .map(|ts| ts.to_utc().to_rfc3339())?;
        tokio::fs::write(&new_meta_path, mtime).await?;

        let body = request
            .bytes()
            .await
            .context("Failed to read MaxMind download response")?;

        let tar_decoder = GzDecoder::new(body.as_ref());
        let mut archive = tar::Archive::new(tar_decoder);

        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;

            if path.extension() == Some(OsStr::new("mmdb")) {
                log::info!("Unpacking database to {}", new_db_path.display());

                // TODO: Make this async, or run in spawn_blocking
                entry
                    .unpack_in(&new_db_path)
                    .context("Failed to unpack database")?;

                let paths = DatabasePaths {
                    db: new_db_path.join(entry.path()?),
                    meta: new_meta_path,
                };

                return Ok(paths);
            }
        }

        Err(anyhow!("No .mmdb file found in tar.gz archive"))
    }
}
