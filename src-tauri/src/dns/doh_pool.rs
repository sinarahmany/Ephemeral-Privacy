use crate::dns::odoh::OdohClient;
use crate::proxy::fingerprint::FingerprintPool;
use rand::seq::IndexedRandom;
use reqwest::Client;
use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, PacketFlag, Question, CLASS, QCLASS, QTYPE, RCODE, TYPE};
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

#[derive(Debug, Clone)]
pub enum ResolveError {
    CnameCloakedTracker {
        original_domain: String,
        canonical_target: Option<String>,
        matched_tracker: String,
    },
    Failed(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::CnameCloakedTracker {
                original_domain,
                canonical_target,
                matched_tracker,
            } => write!(
                f,
                "CNAME cloaked tracker '{}' -> '{}' ({})",
                original_domain,
                canonical_target.as_deref().unwrap_or("unknown"),
                matched_tracker
            ),
            ResolveError::Failed(msg) => write!(f, "{}", msg),
        }
    }
}

#[derive(Clone)]
pub struct DohPool {
    client: Client,
    pub fp_pool: FingerprintPool,
    pub odoh: OdohClient,
    rr_index: Arc<AtomicUsize>,
}

/// Validates that a raw DNS wire response parses cleanly and is not a resolver error
/// (`SERVFAIL`, `REFUSED`, `FORMERR`, or `NOTIMP`). `NXDOMAIN` is treated as a valid answer.
pub(crate) fn validate_dns_reply(resp_bytes: &[u8]) -> Result<(), String> {
    let parsed = Packet::parse(resp_bytes).map_err(|e| format!("Invalid DNS packet: {}", e))?;
    match parsed.rcode() {
        RCODE::FormatError | RCODE::ServerFailure | RCODE::NotImplemented | RCODE::Refused => {
            Err(format!("Upstream DNS returned {:?}", parsed.rcode()))
        }
        _ => Ok(()),
    }
}

impl DohPool {
    pub fn new() -> Self {
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(4))
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| Client::new());

        let fp_pool = FingerprintPool::new();
        let odoh = OdohClient::new(fp_pool.clone());

        Self {
            client,
            fp_pool,
            odoh,
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

    /// Performs an RFC 8484 DNS over HTTPS query with optional JA3 cipher-shuffled profile
    pub async fn query_doh_profiled(
        &self,
        raw_dns_packet: &[u8],
        resolver: &UpstreamResolver,
        ja3_shuffle: bool,
    ) -> Result<Vec<u8>, String> {
        let client = if ja3_shuffle {
            &self.fp_pool.next_profile().client
        } else {
            &self.client
        };

        let resp = client
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

    /// Performs an RFC 8484 DNS over HTTPS query with the specified resolver
    pub async fn query_doh(&self, raw_dns_packet: &[u8], resolver: &UpstreamResolver) -> Result<Vec<u8>, String> {
        self.query_doh_profiled(raw_dns_packet, resolver, true).await
    }

    /// Smart DNS query: attempts RFC 9230 Oblivious DoH Relay first when `use_odoh` is enabled,
    /// seamlessly falling back across rotated DoH upstreams if relays are unreachable or error out.
    /// Returns `(response_bytes, used_odoh, route_or_resolver_name)`.
    pub async fn query_dns_smart(
        &self,
        raw_dns_packet: &[u8],
        use_odoh: bool,
        ja3_shuffle: bool,
    ) -> Result<(Vec<u8>, bool, &'static str), String> {
        if use_odoh {
            match self.odoh.query_odoh(raw_dns_packet, ja3_shuffle).await {
                Ok((resp, route_name)) => {
                    return Ok((resp, true, route_name));
                }
                Err(e) => {
                    eprintln!("[ODOH] Relay notice (falling back to rotated DoH): {}", e);
                }
            }
        }

        let start = self.rr_index.fetch_add(1, Ordering::Relaxed) % RESOLVERS.len();
        let mut last_err = String::from("No DoH resolvers configured");
        for offset in 0..RESOLVERS.len() {
            let resolver = &RESOLVERS[(start + offset) % RESOLVERS.len()];
            match self
                .query_doh_profiled(raw_dns_packet, resolver, ja3_shuffle)
                .await
            {
                Ok(resp) => match validate_dns_reply(&resp) {
                    Ok(()) => return Ok((resp, false, resolver.name)),
                    Err(e) => last_err = format!("{}: {}", resolver.name, e),
                },
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    async fn query_record_ips_verified(
        &self,
        clean: &str,
        qtype: TYPE,
        use_odoh: bool,
        ja3_shuffle: bool,
        block_trackers: bool,
    ) -> Result<(Vec<IpAddr>, bool, &'static str), ResolveError> {
        let name = Name::new(clean).map_err(|e| ResolveError::Failed(e.to_string()))?;
        let mut query = Packet::new_query(rand::random());
        query.set_flags(PacketFlag::RECURSION_DESIRED);
        query.questions.push(Question::new(
            name,
            QTYPE::TYPE(qtype),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let raw_packet = query
            .build_bytes_vec_compressed()
            .map_err(|e| ResolveError::Failed(e.to_string()))?;

        let (resp_bytes, used_odoh, route_name) = self
            .query_dns_smart(&raw_packet, use_odoh, ja3_shuffle)
            .await
            .map_err(ResolveError::Failed)?;

        if block_trackers {
            if let Some(cname_res) = crate::dns::cname::inspect_cname_response(&resp_bytes) {
                if cname_res.is_cloaked_tracker {
                    let rule = cname_res
                        .canonical_target
                        .as_deref()
                        .and_then(crate::dns::sinkhole::match_tracker)
                        .unwrap_or_else(|| {
                            cname_res
                                .matched_tracker
                                .unwrap_or("cname-tracker")
                                .to_string()
                        });
                    return Err(ResolveError::CnameCloakedTracker {
                        original_domain: cname_res.original_domain,
                        canonical_target: cname_res.canonical_target,
                        matched_tracker: rule,
                    });
                }
            }
        }

        let parsed = Packet::parse(&resp_bytes).map_err(|e| ResolveError::Failed(e.to_string()))?;
        let mut ips = Vec::new();
        for ans in &parsed.answers {
            match &ans.rdata {
                RData::A(a) => ips.push(IpAddr::V4(std::net::Ipv4Addr::from(a.address))),
                RData::AAAA(aaaa) => ips.push(IpAddr::V6(std::net::Ipv6Addr::from(aaaa.address))),
                _ => {}
            }
        }

        Ok((ips, used_odoh, route_name))
    }

    /// Resolves all A and fallback AAAA IPs via ODoH/DoH while enforcing real-time CNAME tracker inspection.
    pub async fn resolve_ips_verified(
        &self,
        domain: &str,
        use_odoh: bool,
        ja3_shuffle: bool,
        block_trackers: bool,
    ) -> Result<(Vec<IpAddr>, bool, &'static str), ResolveError> {
        let clean = domain.trim_end_matches('.');
        if let Ok(ip) = clean.parse::<IpAddr>() {
            return Ok((vec![ip], false, "Direct IP"));
        }

        let (mut ips, mut used_odoh, mut route_name) = self
            .query_record_ips_verified(clean, TYPE::A, use_odoh, ja3_shuffle, block_trackers)
            .await?;

        if ips.is_empty() {
            if let Ok((v6_ips, v6_odoh, v6_route)) = self
                .query_record_ips_verified(clean, TYPE::AAAA, use_odoh, ja3_shuffle, block_trackers)
                .await
            {
                if !v6_ips.is_empty() {
                    ips = v6_ips;
                    used_odoh = v6_odoh;
                    route_name = v6_route;
                }
            }
        }

        if ips.is_empty() {
            return Err(ResolveError::Failed(format!("No IP address found for {}", clean)));
        }

        Ok((ips, used_odoh, route_name))
    }

    /// Performs encrypted DNS resolution returning first IP with optional CNAME tracker blocking.
    pub async fn resolve_ip_verified(
        &self,
        domain: &str,
        use_odoh: bool,
        ja3_shuffle: bool,
        block_trackers: bool,
    ) -> Result<(IpAddr, bool, &'static str), ResolveError> {
        let (ips, used_odoh, route_name) = self
            .resolve_ips_verified(domain, use_odoh, ja3_shuffle, block_trackers)
            .await?;
        Ok((ips[0], used_odoh, route_name))
    }

    /// Performs encrypted DNS resolution (ODoH Relay when enabled, rotated DoH fallback)
    /// returning `(IpAddr, used_odoh, route_or_resolver_name)`.
    pub async fn resolve_ip_smart(
        &self,
        domain: &str,
        use_odoh: bool,
        ja3_shuffle: bool,
    ) -> Result<(IpAddr, bool, &'static str), String> {
        self.resolve_ip_verified(domain, use_odoh, ja3_shuffle, false)
            .await
            .map_err(|e| e.to_string())
    }

    /// Legacy wrapper resolving via encrypted DoH
    pub async fn resolve_ip(&self, domain: &str) -> Result<IpAddr, String> {
        let (ip, _, _) = self.resolve_ip_smart(domain, false, true).await?;
        Ok(ip)
    }
}
