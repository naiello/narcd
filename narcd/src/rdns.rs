use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use moka::future::Cache;

pub struct ReverseDns {
    cache: Cache<Ipv4Addr, Option<String>>,
}

impl Default for ReverseDns {
    fn default() -> Self {
        Self::new()
    }
}

impl ReverseDns {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(Duration::from_mins(5))
                .max_capacity(100)
                .build(),
        }
    }

    pub async fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.cache
            .get_with(ip, async move {
                tokio::task::spawn_blocking(move || {
                    dns_lookup::lookup_addr(&IpAddr::V4(ip))
                        .inspect_err(|err| log::debug!("DNS lookup failed: {err}"))
                        .ok()
                })
                .await
                .inspect_err(|err| log::warn!("Reverse DNS lookup cancelled: {err}"))
                .ok()
                .flatten()
            })
            .await
    }
}
