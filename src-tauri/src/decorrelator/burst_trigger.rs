use crate::decorrelator::grammar::{random_decoy_search_url, random_dns_domain};
use crate::dns::doh_pool::DohPool;
use crate::state::{AppState, ChaffIntensity};
use rand::RngExt;
use simple_dns::{Name, Packet, PacketFlag, Question, CLASS, QTYPE, TYPE};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

pub struct DecorrelatorEngine {
    state: Arc<AppState>,
    doh_pool: DohPool,
}

impl DecorrelatorEngine {
    pub fn new(state: Arc<AppState>, doh_pool: DohPool) -> Self {
        Self { state, doh_pool }
    }

    /// Called whenever a genuine query is detected.
    /// Intersperses synthetic, realistic "chaff" queries across multiple upstream resolvers with randomized delays.
    pub fn trigger_chaff_burst(&self, _trigger_source: &str, _real_domain: &str) {
        if !self.state.chaff_enabled.load(Ordering::Relaxed) {
            return;
        }

        let state = self.state.clone();
        let doh_pool = self.doh_pool.clone();

        tauri::async_runtime::spawn(async move {
            let intensity = {
                let guard = state.chaff_intensity.read().await;
                guard.clone()
            };

            let decoy_count = match intensity {
                ChaffIntensity::Ghost => rand::rng().random_range(1..=2),
                ChaffIntensity::Smokescreen => rand::rng().random_range(2..=4),
                ChaffIntensity::HeavyFog => rand::rng().random_range(4..=7),
            };

            for i in 0..decoy_count {
                // Jittered Poisson-like delay: mimics human reading / subsequent asset fetching
                let delay_ms = rand::rng().random_range(250..2800) + (i * 350);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                // Pick a random decoy domain
                let decoy_domain = random_dns_domain();

                // Rotate to a different upstream resolver for each decoy query!
                let resolver = doh_pool.random_resolver(None);

                // Build a valid raw DNS wire-format packet with RD=1 like standard client resolvers
                if let Ok(name) = Name::new(decoy_domain) {
                    let mut packet = Packet::new_query(rand::rng().random());
                    packet.set_flags(PacketFlag::RECURSION_DESIRED);
                    packet.questions.push(Question::new(
                        name,
                        QTYPE::TYPE(TYPE::A),
                        simple_dns::QCLASS::CLASS(CLASS::IN),
                        false,
                    ));

                    if let Ok(raw_query) = packet.build_bytes_vec_compressed() {
                        let use_odoh = state.odoh_enabled.load(Ordering::Relaxed);
                        let ja3 = state.ja3_shuffle.load(Ordering::Relaxed);
                        // Dispatch decoy via JA3-shuffled / ODoH smart DNS path
                        if let Ok((_, used_odoh, route_label)) = doh_pool
                            .query_dns_smart(&raw_query, use_odoh, ja3)
                            .await
                        {
                            state.chaff_queries_sent.fetch_add(1, Ordering::Relaxed);
                            if ja3 {
                                state.ja3_fingerprints_shuffled.fetch_add(1, Ordering::Relaxed);
                            }
                            if used_odoh {
                                state.odoh_queries_relayed.fetch_add(1, Ordering::Relaxed);
                            }
                            let _ = resolver; // resolver kept for fallback logging
                            state
                                .log_event(
                                    "DNS_CHAFF",
                                    &format!("Decoy Query Interspersed (+{}ms)", delay_ms),
                                    &format!("Sent decoy '{}' via {}", decoy_domain, route_label),
                                    decoy_domain,
                                )
                                .await;
                        }
                    }
                }

                // If on HeavyFog, also occasionally generate a search engine decoy GET
                if matches!(intensity, ChaffIntensity::HeavyFog) && i == 0 {
                    let search_url = random_decoy_search_url();
                    let ja3 = state.ja3_shuffle.load(Ordering::Relaxed);
                    let (client, ua) = if ja3 {
                        let prof = doh_pool.fp_pool.random_profile();
                        (prof.client.clone(), prof.user_agent)
                    } else {
                        (
                            reqwest::Client::builder()
                                .no_proxy()
                                .timeout(Duration::from_secs(3))
                                .build()
                                .unwrap_or_default(),
                            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                        )
                    };

                    let _ = client
                        .get(&search_url)
                        .header("user-agent", ua)
                        .send()
                        .await;

                    state.chaff_queries_sent.fetch_add(1, Ordering::Relaxed);
                    state
                        .log_event(
                            "SEARCH_CHAFF",
                            "Synthetic Search Query Dispatched",
                            "Blended decoy search to privacy engine",
                            &search_url,
                        )
                        .await;
                }
            }
        });
    }
}
