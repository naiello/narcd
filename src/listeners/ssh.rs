use rand_core::OsRng;
use russh::keys;
use russh::server::{self, Auth, Server as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct SshServer;

pub struct SshHandler {
    pub peer_addr: Option<SocketAddr>,
}

impl server::Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        SshHandler { peer_addr }
    }
}

impl server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> Result<server::Auth, Self::Error> {
        log::info!("auth attempt by {}", user);
        Ok(Auth::reject())
    }
}

pub async fn start_server() -> Result<(), std::io::Error> {
    let key = keys::PrivateKey::random(&mut OsRng, keys::Algorithm::Rsa { hash: None })
        .expect("Could not generate private key");

    let config = server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        max_auth_attempts: 5,
        keys: vec![key],
        ..Default::default()
    };

    let config = Arc::new(config);
    let mut server = SshServer;

    log::info!("server running on 0.0.0.0:2222");
    server.run_on_address(config, ("0.0.0.0", 2222)).await
}
