pub mod cname;
pub mod doh_pool;
pub mod odoh;
pub mod sinkhole;

use crate::decorrelator::DecorrelatorEngine;
use crate::dns::cname::{build_sinkhole_response, inspect_cname_response};
use crate::dns::doh_pool::DohPool;
use crate::dns::sinkhole::is_tracker;
use crate::proxy::webrtc_shield::is_webrtc_stun_target;
use crate::state::AppState;
use simple_dns::Packet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct DnsServer {
    state: Arc<AppState>,
    doh_pool: DohPool,
    decorrelator: Arc<DecorrelatorEngine>,
}

impl DnsServer {
    pub fn new(
        state: Arc<AppState>,
        doh_pool: DohPool,
        decorrelator: Arc<DecorrelatorEngine>,
    ) -> Self {
        Self {
            state,
            doh_pool,
            decorrelator,
        }
    }

    pub async fn run_auto(&self) -> Result<u16, String> {
        let candidate_ports = [5300, 1053, 5354, 8553];
        for port in candidate_ports {
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
            match UdpSocket::bind(addr).await {
                Ok(socket) => {
                    println!("[DNS] Bound successfully on 127.0.0.1:{}", port);
                    let socket = Arc::new(socket);
                    let mut buf = [0u8; 4096];

                    loop {
                        let (len, client_addr) = match socket.recv_from(&mut buf).await {
                            Ok(res) => res,
                            Err(e) => {
                                eprintln!("DNS recv error: {}", e);
                                continue;
                            }
                        };

                        if !self.state.dns_enabled.load(Ordering::Relaxed) {
                            continue;
                        }

                        let query_bytes = buf[..len].to_vec();
                        let socket_clone = socket.clone();
                        let state = self.state.clone();
                        let doh_pool = self.doh_pool.clone();
                        let decorrelator = self.decorrelator.clone();

                        tokio::spawn(async move {
                            handle_dns_query(
                                query_bytes,
                                client_addr,
                                socket_clone,
                                state,
                                doh_pool,
                                decorrelator,
                            )
                            .await;
                        });
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }
        Err("Failed to bind DNS UDP server on any candidate port (5300, 1053, 5354)".into())
    }
}

async fn handle_dns_query(
    query_bytes: Vec<u8>,
    client_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    state: Arc<AppState>,
    doh_pool: DohPool,
    decorrelator: Arc<DecorrelatorEngine>,
) {
    let packet = match Packet::parse(&query_bytes) {
        Ok(p) => p,
        Err(_) => return,
    };

    let question = match packet.questions.first() {
        Some(q) => q,
        None => return,
    };

    let domain = question.qname.to_string();
    let clean_domain = domain.trim_end_matches('.');

    // 1. WebRTC STUN/TURN Leak Shield Check
    if state.webrtc_shield.load(Ordering::Relaxed) {
        if let Some(reason) = is_webrtc_stun_target(clean_domain, None) {
            state.webrtc_leaks_blocked.fetch_add(1, Ordering::Relaxed);
            state
                .log_event(
                    "WEBRTC_BLOCKED",
                    "WebRTC IP Leak Blocked (DNS)",
                    &format!("Blocked {} ({}) to prevent LAN/WAN IP exposure", clean_domain, reason),
                    clean_domain,
                )
                .await;

            if let Some(sinkhole_resp) = build_sinkhole_response(&query_bytes) {
                let _ = socket.send_to(&sinkhole_resp, client_addr).await;
            }
            return;
        }
    }

    // 2. Direct Sinkhole Tracker Check
    if let Some(tracker_name) = is_tracker(clean_domain) {
        state.trackers_blocked.fetch_add(1, Ordering::Relaxed);
        state
            .log_event(
                "TRACKER_BLOCKED",
                &format!("Ad/Tracker Sinkholed: {}", tracker_name),
                &format!("Intercepted and blocked DNS request for {}", clean_domain),
                clean_domain,
            )
            .await;

        if let Some(sinkhole_resp) = build_sinkhole_response(&query_bytes) {
            let _ = socket.send_to(&sinkhole_resp, client_addr).await;
        }
        return;
    }

    // 3. Legitimate query: Record metrics and trigger Ephemeral Chaff Decoy burst!
    state.queries_intercepted.fetch_add(1, Ordering::Relaxed);
    decorrelator.trigger_chaff_burst("DNS", clean_domain);

    let use_odoh = state.odoh_enabled.load(Ordering::Relaxed);
    let ja3_shuffle = state.ja3_shuffle.load(Ordering::Relaxed);

    // 4. Forward via ODoH Relay (when enabled) or Encrypted DoH Pool
    match doh_pool.query_dns_smart(&query_bytes, use_odoh, ja3_shuffle).await {
        Ok((resp_bytes, used_odoh, route_name)) => {
            if used_odoh {
                state.odoh_queries_relayed.fetch_add(1, Ordering::Relaxed);
            }
            if ja3_shuffle {
                state.ja3_fingerprints_shuffled.fetch_add(1, Ordering::Relaxed);
            }

            // 5. Inspect response for CNAME Cloaking
            if let Some(cname_res) = inspect_cname_response(&resp_bytes) {
                if cname_res.is_cloaked_tracker {
                    state.trackers_blocked.fetch_add(1, Ordering::Relaxed);
                    state
                        .log_event(
                            "TRACKER_BLOCKED",
                            "CNAME Cloaked Tracker Unmasked & Blocked",
                            &format!(
                                "Domain '{}' cloaked target '{}' ({})",
                                cname_res.original_domain,
                                cname_res.canonical_target.as_deref().unwrap_or(""),
                                cname_res.matched_tracker.unwrap_or("")
                            ),
                            &clean_domain,
                        )
                        .await;

                    if let Some(sinkhole_resp) = build_sinkhole_response(&query_bytes) {
                        let _ = socket.send_to(&sinkhole_resp, client_addr).await;
                    }
                    return;
                }
            }

            let _ = route_name;
            // Normal legitimate response
            let _ = socket.send_to(&resp_bytes, client_addr).await;
        }
        Err(e) => {
            eprintln!("DoH/ODoH resolution failed for {}: {}", clean_domain, e);
        }
    }
}
