use crate::proxy::fingerprint::FingerprintPool;
use odoh_rs::{
    compose, decrypt_response, encrypt_query, parse, ObliviousDoHConfigContents,
    ObliviousDoHConfigs, ObliviousDoHMessagePlaintext, ODOH_HTTP_HEADER,
};
use rand::RngExt;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct OdohRoute {
    pub name: &'static str,
    pub relay_url: &'static str,
    pub target_host: &'static str,
    pub target_path: &'static str,
}

/// Non-colluding ODoH Relay + Target pairings (RFC 9230):
/// Relay knows client IP but cannot decrypt query; Target decrypts query but only sees Relay IP.
pub static ODOH_ROUTES: &[OdohRoute] = &[
    OdohRoute {
        name: "Fastly Relay -> Cloudflare Target",
        relay_url: "https://odoh-relay.edgecompute.app/proxy",
        target_host: "odoh.cloudflare-dns.com",
        target_path: "/dns-query",
    },
    OdohRoute {
        name: "Numa Relay -> Crypto.sx Target",
        relay_url: "https://odoh-relay.numa.rs/relay",
        target_host: "odoh.crypto.sx",
        target_path: "/dns-query",
    },
    OdohRoute {
        name: "Fastly Relay -> Crypto.sx Target",
        relay_url: "https://odoh-relay.edgecompute.app/proxy",
        target_host: "odoh.crypto.sx",
        target_path: "/dns-query",
    },
];

struct CachedTargetConfig {
    contents: ObliviousDoHConfigContents,
    fetched_at: Instant,
}

#[derive(Clone)]
pub struct OdohClient {
    fallback_client: Client,
    fp_pool: FingerprintPool,
    configs: Arc<RwLock<HashMap<String, CachedTargetConfig>>>,
    rr_index: Arc<AtomicUsize>,
}

impl OdohClient {
    pub fn new(fp_pool: FingerprintPool) -> Self {
        let fallback_client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            fallback_client,
            fp_pool,
            configs: Arc::new(RwLock::new(HashMap::new())),
            rr_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn next_route(&self) -> &'static OdohRoute {
        let idx = self.rr_index.fetch_add(1, Ordering::Relaxed) % ODOH_ROUTES.len();
        &ODOH_ROUTES[idx]
    }

    async fn get_target_config(
        &self,
        target_host: &str,
        ja3_shuffle: bool,
    ) -> Result<ObliviousDoHConfigContents, String> {
        {
            let guard = self.configs.read().await;
            if let Some(entry) = guard.get(target_host) {
                if entry.fetched_at.elapsed() < Duration::from_secs(900) {
                    return Ok(entry.contents.clone());
                }
            }
        }

        let conf_url = format!("https://{}/.well-known/odohconfigs", target_host);
        let client = if ja3_shuffle {
            &self.fp_pool.next_profile().client
        } else {
            &self.fallback_client
        };

        let resp = client
            .get(&conf_url)
            .send()
            .await
            .map_err(|e| format!("Failed fetching ODoH configs from {}: {}", target_host, e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "ODoH config fetch {} returned HTTP {}",
                target_host,
                resp.status()
            ));
        }

        let mut bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed reading ODoH config body: {}", e))?;

        let parsed: ObliviousDoHConfigs =
            parse(&mut bytes).map_err(|e| format!("Invalid ODoH config format: {:?}", e))?;
        let first_config = parsed
            .into_iter()
            .next()
            .ok_or_else(|| "Empty ODoH config list from target".to_string())?;
        let contents: ObliviousDoHConfigContents = first_config.into();

        {
            let mut guard = self.configs.write().await;
            guard.insert(
                target_host.to_string(),
                CachedTargetConfig {
                    contents: contents.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(contents)
    }

    /// Executes an RFC 9230 Oblivious DoH DNS lookup through a non-colluding Relay -> Target pair.
    pub async fn query_odoh(
        &self,
        raw_dns_packet: &[u8],
        ja3_shuffle: bool,
    ) -> Result<(Vec<u8>, &'static str), String> {
        let route = self.next_route();
        let config_contents = self.get_target_config(route.target_host, ja3_shuffle).await?;

        // Build and HPKE-encrypt the query synchronously before any `.await` so ThreadRng is dropped cleanly
        let (query_plaintext, cli_secret, query_body) = {
            let mut rng = rand::rng();
            let padding_len = rng.random_range(4..24);
            let query_plaintext = ObliviousDoHMessagePlaintext::new(raw_dns_packet, padding_len);
            let (query_enc, cli_secret) =
                encrypt_query(&query_plaintext, &config_contents, &mut rng)
                    .map_err(|e| format!("ODoH HPKE encrypt failed: {:?}", e))?;
            let query_body = compose(&query_enc)
                .map_err(|e| format!("ODoH compose failed: {:?}", e))?
                .freeze();
            (query_plaintext, cli_secret, query_body)
        };

        let relay_request_url = format!(
            "{}?targethost={}&targetpath={}",
            route.relay_url, route.target_host, route.target_path
        );

        let client = if ja3_shuffle {
            &self.fp_pool.next_profile().client
        } else {
            &self.fallback_client
        };

        let resp = client
            .post(&relay_request_url)
            .header("content-type", ODOH_HTTP_HEADER)
            .header("accept", ODOH_HTTP_HEADER)
            .body(query_body)
            .send()
            .await
            .map_err(|e| format!("ODoH relay {} connection failed: {}", route.relay_url, e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "ODoH relay {} returned HTTP {}",
                route.name,
                resp.status()
            ));
        }

        let mut resp_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed reading ODoH relay response: {}", e))?;

        let response_enc =
            parse(&mut resp_bytes).map_err(|e| format!("Failed parsing ODoH response: {:?}", e))?;
        let response_dec = decrypt_response(&query_plaintext, &response_enc, cli_secret)
            .map_err(|e| format!("ODoH HPKE decryption failed: {:?}", e))?;

        Ok((response_dec.into_msg().to_vec(), route.name))
    }
}
