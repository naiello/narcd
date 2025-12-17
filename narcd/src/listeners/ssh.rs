use crate::events::{SshAuthMethod, SshLogin};
use crate::logger::EventLogger;
use crate::metadata::Metadata;
use anyhow::Result;
use chrono::Utc;
use rand_core::OsRng;
use russh::keys;
use russh::server::{self, Auth, Server as _};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize)]
pub struct SshConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub inactivity_timeout: Duration,
    pub auth_rejection_time: Duration,
    pub max_auth_attempts: usize,
    pub host_key_file: String,
    pub server_id: String,
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            listen_addr: "0.0.0.0".to_owned(),
            listen_port: 22,
            auth_rejection_time: Duration::from_secs(1),
            inactivity_timeout: Duration::from_secs(3600),
            max_auth_attempts: 5,
            host_key_file: "/var/db/narcd/ssh_hostkey".to_owned(),
            server_id: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u5".to_owned(),
        }
    }
}

#[derive(Clone)]
pub struct SshServer<L: EventLogger<SshLogin>> {
    pub logger: L,
    pub metadata: Arc<Metadata>,
}

pub struct SshHandler<L: EventLogger<SshLogin>> {
    pub peer_addr: Option<SocketAddr>,
    pub logger: L,
    pub metadata: Arc<Metadata>,
}

impl<L: EventLogger<SshLogin> + 'static> server::Server for SshServer<L> {
    type Handler = SshHandler<L>;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        SshHandler {
            peer_addr,
            logger: self.logger.clone(),
            metadata: self.metadata.clone(),
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
        let event = SshLogin {
            ts: Utc::now(),
            src_ip: self.peer_addr.map(|addr| addr.ip()),
            src_port: self.peer_addr.map(|addr| addr.port()),
            username: user.to_string(),
            auth: SshAuthMethod::Password {
                password: password.to_string(),
            },
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
        let key_fingerprint = public_key.fingerprint(keys::HashAlg::Sha256).to_string();
        let event = SshLogin {
            ts: Utc::now(),
            src_ip: self.peer_addr.map(|addr| addr.ip()),
            src_port: self.peer_addr.map(|addr| addr.port()),
            username: user.to_string(),
            auth: SshAuthMethod::PublicKey {
                key_fingerprint,
                key_comment: public_key.comment().to_string(),
                key_algorithm: public_key.algorithm().to_string(),
            },
            metadata: self.metadata.as_ref().clone(),
        };
        self.logger.log_event(event).await?;
        Ok(Auth::reject())
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

pub async fn start_server<L: EventLogger<SshLogin> + 'static>(
    config: &SshConfig,
    metadata: Arc<Metadata>,
    logger: L,
) -> Result<()> {
    let key = get_or_create_host_key(config).await?;
    let addr = (config.listen_addr.clone(), config.listen_port);
    let config = server::Config {
        inactivity_timeout: Some(config.inactivity_timeout),
        auth_rejection_time: config.auth_rejection_time,
        max_auth_attempts: config.max_auth_attempts,
        server_id: russh::SshId::Standard(config.server_id.clone()),
        keys: vec![key],
        ..Default::default()
    };

    let config = Arc::new(config);
    let mut server = SshServer { logger, metadata };

    log::info!("starting ssh listener on {}:{}", addr.0, addr.1);
    Ok(server.run_on_address(config, addr).await?)
}
