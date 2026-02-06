use crate::events::{SshAuthMethod, SshLogin};
use crate::ipasn::IpAsnDb;
use crate::ipgeo::IpGeoDb;
use crate::logger::EventLogger;
use crate::metadata::Metadata;
use crate::rdns::ReverseDns;
use anyhow::Result;
use chrono::Utc;
use rand_core::OsRng;
use russh::keys;
use russh::server::{self, Auth, Server as _};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio_graceful::ShutdownGuard;
use tokio_util::task::AbortOnDropHandle;

#[derive(Deserialize)]
pub struct SshConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub inactivity_timeout_secs: u64,
    pub auth_rejection_time_secs: u64,
    pub max_auth_attempts: usize,
    pub host_key_file: String,
    pub server_id: String,
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            listen_addr: "0.0.0.0".to_owned(),
            listen_port: 22,
            auth_rejection_time_secs: 1,
            inactivity_timeout_secs: 3600,
            max_auth_attempts: 5,
            host_key_file: "/var/db/narcd/ssh_hostkey".to_owned(),
            server_id: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5".to_owned(),
        }
    }
}

impl SshConfig {
    fn auth_rejection_time(&self) -> Duration {
        Duration::from_secs(self.auth_rejection_time_secs)
    }

    fn inactivity_timeout(&self) -> Duration {
        Duration::from_secs(self.inactivity_timeout_secs)
    }
}

#[derive(Clone)]
pub struct SshServer<L: EventLogger<SshLogin>> {
    pub logger: L,
    pub metadata: Arc<Metadata>,
    pub ipasn_db: Arc<IpAsnDb>,
    pub ipgeo_db: Arc<IpGeoDb>,
    pub rdns: Arc<ReverseDns>,
}

pub struct SshHandler<L: EventLogger<SshLogin>> {
    pub peer_addr: Option<SocketAddr>,
    pub logger: L,
    pub metadata: Arc<Metadata>,
    pub ipasn_db: Arc<IpAsnDb>,
    pub ipgeo_db: Arc<IpGeoDb>,
    pub rdns: Arc<ReverseDns>,
}

impl<L: EventLogger<SshLogin> + 'static> server::Server for SshServer<L> {
    type Handler = SshHandler<L>;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        SshHandler {
            peer_addr,
            logger: self.logger.clone(),
            metadata: self.metadata.clone(),
            ipasn_db: self.ipasn_db.clone(),
            ipgeo_db: self.ipgeo_db.clone(),
            rdns: self.rdns.clone(),
        }
    }
}

impl<L: EventLogger<SshLogin>> server::Handler for SshHandler<L> {
    type Error = anyhow::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        let src_ip = self.peer_addr.map(|addr| addr.ip());
        let src_ip_as = match src_ip {
            Some(IpAddr::V4(ipv4)) => self.ipasn_db.lookup(ipv4).await,
            _ => None,
        };

        let src_ip_geo = match src_ip {
            Some(IpAddr::V4(ipv4)) => self.ipgeo_db.lookup(ipv4).await,
            _ => None,
        };

        let src_hostname = match src_ip {
            Some(IpAddr::V4(ipv4)) => self.rdns.lookup(ipv4).await,
            _ => None,
        };

        let event = SshLogin {
            ts: Utc::now(),
            src_ip,
            src_port: self.peer_addr.map(|addr| addr.port()),
            username: user.to_string(),
            auth: SshAuthMethod::Password {
                password: password.to_string(),
            },
            src_ip_as,
            src_ip_geo,
            src_hostname,
            metadata: self.metadata.as_ref().clone(),
        };
        self.logger.log_event(event).await?;
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let src_ip = self.peer_addr.map(|addr| addr.ip());
        let src_ip_as = match src_ip {
            Some(IpAddr::V4(ipv4)) => self.ipasn_db.lookup(ipv4).await,
            _ => None,
        };

        let src_ip_geo = match src_ip {
            Some(IpAddr::V4(ipv4)) => self.ipgeo_db.lookup(ipv4).await,
            _ => None,
        };

        let src_hostname = match src_ip {
            Some(IpAddr::V4(ipv4)) => self.rdns.lookup(ipv4).await,
            _ => None,
        };

        let key_fingerprint = public_key.fingerprint(keys::HashAlg::Sha256).to_string();
        let event = SshLogin {
            ts: Utc::now(),
            src_ip,
            src_port: self.peer_addr.map(|addr| addr.port()),
            username: user.to_string(),
            auth: SshAuthMethod::PublicKey {
                key_fingerprint,
                key_comment: public_key.comment().to_string(),
                key_algorithm: public_key.algorithm().to_string(),
            },
            src_ip_as,
            src_ip_geo,
            src_hostname,
            metadata: self.metadata.as_ref().clone(),
        };
        self.logger.log_event(event).await?;
        Ok(Auth::reject())
    }
}

pub struct SshServerHandle {
    _server_task: AbortOnDropHandle<()>,
}

impl<L: EventLogger<SshLogin> + 'static> SshServer<L> {
    pub async fn start(
        config: &SshConfig,
        metadata: Arc<Metadata>,
        logger: L,
        ipasn_db: Arc<IpAsnDb>,
        ipgeo_db: Arc<IpGeoDb>,
        rdns: Arc<ReverseDns>,
        shutdown: ShutdownGuard,
    ) -> Result<SshServerHandle> {
        let key = get_or_create_host_key(config).await?;
        let addr = (config.listen_addr.clone(), config.listen_port);
        let config = server::Config {
            inactivity_timeout: Some(config.inactivity_timeout()),
            auth_rejection_time: config.auth_rejection_time(),
            max_auth_attempts: config.max_auth_attempts,
            server_id: russh::SshId::Standard(config.server_id.clone()),
            keys: vec![key],
            ..Default::default()
        };

        let config = Arc::new(config);
        let mut server = SshServer {
            logger,
            metadata,
            ipasn_db,
            ipgeo_db,
            rdns,
        };

        log::info!("starting ssh listener on {}:{}", addr.0, addr.1);
        let task = shutdown.into_spawn_task_fn(|guard| async move {
            select! {
                res = server.run_on_address(config, addr) => {
                    match res {
                        Ok(_) => {
                            log::warn!("SSH server exited unexpectedly");
                        }
                        Err(err) => {
                            log::error!("SSH server died: {err}");
                        }
                    }
                },
                _ = guard.cancelled() => {
                    log::info!("SSH server shutting down");
                }
            }
        });

        Ok(SshServerHandle {
            _server_task: AbortOnDropHandle::new(task),
        })
    }
}

async fn create_host_key(filename: &str) -> Result<keys::PrivateKey> {
    log::info!("generating new ssh hostkey");
    let key = keys::PrivateKey::random(&mut OsRng, keys::Algorithm::Rsa { hash: None })?;
    tokio::fs::write(filename, key.to_openssh(keys::ssh_key::LineEnding::LF)?).await?;
    Ok(key)
}

async fn get_or_create_host_key(config: &SshConfig) -> Result<keys::PrivateKey> {
    match tokio::fs::read(&config.host_key_file).await {
        Ok(bytes) => Ok(keys::PrivateKey::from_openssh(bytes)?),
        Err(_) => Ok(create_host_key(&config.host_key_file).await?),
    }
}
