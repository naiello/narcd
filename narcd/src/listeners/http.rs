use crate::events::{HttpAuthMethod, HttpRequest, Observables};
use crate::ipasn::IpAsnDb;
use crate::ipgeo::IpGeoDb;
use crate::logger::EventLogger;
use crate::metadata::Metadata;
use crate::observables::{merge_common, merge_http};
use crate::rdns::ReverseDns;
use crate::util::Shared;
use anyhow::Result;
use base64::prelude::*;
use chrono::Utc;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_graceful::ShutdownGuard;
use tokio_util::task::AbortOnDropHandle;

#[derive(Deserialize, Clone)]
pub struct HttpConfig {
    pub listen_addr: String,
    pub listen_ports: Vec<u16>,
    pub response_status: u16,
    pub max_body_size: usize,
    pub max_header_size: usize,
    pub connection_timeout_secs: u64,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            listen_addr: "0.0.0.0".to_owned(),
            listen_ports: vec![80],
            response_status: 403,
            max_body_size: 4096,
            max_header_size: 8192,
            connection_timeout_secs: 30,
        }
    }
}

impl HttpConfig {
    fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }

    fn effective_ports(&self) -> &[u16] {
        if self.listen_ports.is_empty() {
            log::warn!("HTTP listen_ports is empty, using default port 80");
            &[80]
        } else {
            self.listen_ports.as_ref()
        }
    }
}

#[derive(Clone)]
pub struct HttpServer<L: EventLogger<HttpRequest>> {
    pub logger: L,
    pub metadata: Arc<Metadata>,
    pub config: Arc<HttpConfig>,
    pub ipasn_db: Arc<IpAsnDb>,
    pub ipgeo_db: Arc<IpGeoDb>,
    pub rdns: Arc<ReverseDns>,
}

pub struct HttpServerHandle {
    _server_tasks: Vec<Arc<AbortOnDropHandle<()>>>,
}

impl<L: EventLogger<HttpRequest> + Clone + Shared + 'static> HttpServer<L> {
    pub async fn start(
        config: &HttpConfig,
        metadata: Arc<Metadata>,
        logger: L,
        ipasn_db: Arc<IpAsnDb>,
        ipgeo_db: Arc<IpGeoDb>,
        rdns: Arc<ReverseDns>,
        shutdown: ShutdownGuard,
    ) -> Result<HttpServerHandle> {
        let config = Arc::new(config.clone());
        let server = Arc::new(HttpServer {
            logger,
            metadata,
            config: config.clone(),
            ipasn_db,
            ipgeo_db,
            rdns,
        });

        let mut server_tasks = Vec::new();

        for port in config.effective_ports().iter().copied() {
            let addr = format!("{}:{}", config.listen_addr, port).parse::<SocketAddr>()?;
            let listener = TcpListener::bind(addr).await?;
            log::info!("starting http listener on {}", addr);

            let server = server.clone();
            let config = config.clone();

            let task = shutdown.spawn_task_fn(move |guard| {
                Self::run_listener(listener, server, config, port, guard)
            });

            server_tasks.push(Arc::new(AbortOnDropHandle::new(task)));
        }

        Ok(HttpServerHandle {
            _server_tasks: server_tasks,
        })
    }

    async fn run_listener(
        listener: TcpListener,
        server: Arc<Self>,
        config: Arc<HttpConfig>,
        port: u16,
        guard: ShutdownGuard,
    ) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let io = TokioIo::new(stream);
                            let server = server.clone();
                            let timeout = config.connection_timeout();

                            guard.spawn_task(async move {
                                let service = service_fn(move |req| {
                                    let server = server.clone();
                                    async move { server.handle_request(req, peer_addr, port).await }
                                });

                                let conn = http1::Builder::new().serve_connection(io, service);

                                if let Err(e) = tokio::time::timeout(timeout, conn).await {
                                    log::debug!("connection timeout from {}: {:?}", peer_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Failed to accept connection on port {}: {}", port, e);
                        }
                    }
                }
                _ = guard.cancelled() => {
                    log::info!("HTTP listener on port {} shutting down", port);
                    break;
                }
            }
        }
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
        dst_port: u16,
    ) -> Result<Response<String>> {
        let (parts, incoming_body) = req.into_parts();
        let method = parts.method.to_string();
        let path = parts.uri.path().to_string();
        let headers = parts.headers;

        let user_agent = try_extract_header(&headers, "user-agent");
        let referer = try_extract_header(&headers, "referer");
        let host = try_extract_header(&headers, "host");
        let content_type = try_extract_header(&headers, "content-type");

        let auth = extract_auth(&headers);

        let (body, body_size, body_truncated) =
            read_body_with_limit(incoming_body, self.config.max_body_size).await?;

        let mut obs = Observables::default();
        merge_common(&path, &mut obs);
        if let Some(body_str) = &body {
            merge_common(body_str, &mut obs);
            merge_http(body_str, &method, &headers, &mut obs);
        } else {
            merge_http("", &method, &headers, &mut obs);
        }

        let src_ip = peer_addr.ip();
        let src_ip_as = match src_ip {
            IpAddr::V4(ipv4) => self.ipasn_db.lookup(ipv4).await,
            _ => None,
        };

        let src_ip_geo = match src_ip {
            IpAddr::V4(ipv4) => self.ipgeo_db.lookup(ipv4).await,
            _ => None,
        };

        let src_hostname = match src_ip {
            IpAddr::V4(ipv4) => self.rdns.lookup(ipv4).await,
            _ => None,
        };

        let event = HttpRequest {
            ts: Utc::now(),
            method,
            path,
            src_ip,
            src_port: peer_addr.port(),
            dst_port,
            auth,
            user_agent,
            referer,
            host,
            content_type,
            body,
            body_size,
            body_truncated,
            src_ip_as,
            src_ip_geo,
            src_hostname,
            metadata: self.metadata.as_ref().clone(),
            observables: obs,
        };

        self.logger.log_event(event).await?;

        let status =
            StatusCode::from_u16(self.config.response_status).unwrap_or(StatusCode::FORBIDDEN);
        Ok(Response::builder().status(status).body(String::new())?)
    }
}

fn try_extract_header(headers: &hyper::HeaderMap, header: &str) -> Option<String> {
    headers
        .get(header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn extract_auth(headers: &hyper::HeaderMap) -> HttpAuthMethod {
    let auth_str = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return HttpAuthMethod::None,
    };

    let basic_auth = auth_str
        .strip_prefix("Basic ")
        .and_then(|basic_part| BASE64_STANDARD.decode(basic_part).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|s| {
            s.split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        });

    match basic_auth {
        Some((username, password)) => HttpAuthMethod::Basic { username, password },
        None => HttpAuthMethod::Other {
            value: auth_str.to_string(),
        },
    }
}

async fn read_body_with_limit(
    body: Incoming,
    max_size: usize,
) -> Result<(Option<String>, usize, bool)> {
    let collected = body.collect().await?;
    let bytes = collected.to_bytes();
    let body_size = bytes.len();
    let body_truncated = body_size > max_size;

    if body_size == 0 {
        return Ok((None, 0, false));
    }

    let bytes_to_read = body_size.min(max_size);
    let body_str = String::from_utf8_lossy(&bytes[..bytes_to_read]).to_string();

    Ok((Some(body_str), body_size, body_truncated))
}
