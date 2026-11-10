use rand::seq::IndexedRandom;
use reqwest::Client;
use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, Question, CLASS, QCLASS, QTYPE, TYPE};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct UpstreamResolver {
    pub name: &'static str,
    pub doh_url: &'static str,
    pub is_private: bool,
}

pub static RESOLVERS: &[UpstreamResolver] = &[
    UpstreamResolver {
        name: "Quad9 (Malware/Tracker Blocked)",
        doh_url: "https://dns.quad9.net/dns-query",
        is_private: true,
    },
    UpstreamResolver {
        name: "Mullvad (Zero-Log Privacy)",
        doh_url: "https://dns.mullvad.net/dns-query",
        is_private: true,
    },
    UpstreamResolver {
        name: "Cloudflare (1.1.1.1)",
        doh_url: "https://cloudflare-dns.com/dns-query",
        is_private: false,
    },
    UpstreamResolver {
        name: "LibreDNS (Community Encrypted)",
        doh_url: "https://doh.libredns.gr/dns-query",
        is_private: true,
    },
];

#[derive(Clone)]
pub struct DohPool {
    client: Client,
    rr_index: Arc<AtomicUsize>,
}

impl DohPool {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(4))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            rr_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Selects the next resolver in round-robin fashion for decorrelation
    pub fn next_resolver(&self) -> &'static UpstreamResolver {
        let idx = self.rr_index.fetch_add(1, Ordering::Relaxed) % RESOLVERS.len();
        &RESOLVERS[idx]
    }

    /// Selects a random resolver, optionally excluding a specific one
    pub fn random_resolver(&self, exclude: Option<&str>) -> &'static UpstreamResolver {
        let mut rng = rand::rng();
        let candidates: Vec<&UpstreamResolver> = RESOLVERS
            .iter()
            .filter(|r| exclude.map_or(true, |ex| r.name != ex))
            .collect();

        candidates.choose(&mut rng).copied().unwrap_or(&RESOLVERS[0])
    }

    /// Performs an RFC 8484 DNS over HTTPS query with the specified resolver
    pub async fn query_doh(&self, raw_dns_packet: &[u8], resolver: &UpstreamResolver) -> Result<Vec<u8>, String> {
        let resp = self
            .client
            .post(resolver.doh_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(raw_dns_packet.to_vec())
            .send()
            .await
            .map_err(|e| format!("DoH connection error to {}: {}", resolver.name, e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "DoH upstream {} returned HTTP status {}",
                resolver.name,
                resp.status()
            ));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed reading DoH response: {}", e))?;

        Ok(bytes.to_vec())
    }

    /// Performs an encrypted DNS over HTTPS resolution to retrieve an IP for a domain.
    /// This blinds the local ISP from seeing any plaintext DNS queries for visited websites.
    pub async fn resolve_ip(&self, domain: &str) -> Result<IpAddr, String> {
        let clean = domain.trim_end_matches('.');
        // Check if already an IP
        if let Ok(ip) = clean.parse::<IpAddr>() {
            return Ok(ip);
        }

        let name = Name::new(clean).map_err(|e| e.to_string())?;
        let mut query = Packet::new_query(rand::random());
        query.questions.push(Question::new(
            name,
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let raw_packet = query.build_bytes_vec_compressed().map_err(|e| e.to_string())?;

        let resolver = self.next_resolver();
        let resp_bytes = self.query_doh(&raw_packet, resolver).await?;
        let parsed = Packet::parse(&resp_bytes).map_err(|e| e.to_string())?;

        for ans in &parsed.answers {
            match &ans.rdata {
                RData::A(a) => {
                    return Ok(IpAddr::V4(std::net::Ipv4Addr::from(a.address)));
                }
                RData::AAAA(aaaa) => {
                    return Ok(IpAddr::V6(std::net::Ipv6Addr::from(aaaa.address)));
                }
                _ => {}
            }
        }

        Err(format!("No IP address found for {}", clean))
    }
}
