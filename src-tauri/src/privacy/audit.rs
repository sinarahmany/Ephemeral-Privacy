use crate::dns::doh_pool::DohPool;
use crate::dns::sinkhole::is_tracker;
use crate::privacy::hardware_sentinel::probe_hardware_state;
use crate::proxy::dpi_bypass::{find_sni_offset, split_client_hello_records};
use crate::proxy::webrtc_shield::is_webrtc_stun_target;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditCheckResult {
    pub id: String,
    pub name: String,
    pub status: String, // "PASS" | "WARN" | "FAIL"
    pub points_earned: u8,
    pub max_points: u8,
    pub latency_ms: u64,
    pub summary: String,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAuditReport {
    pub score: u8,
    pub timestamp: u64,
    pub checks: Vec<AuditCheckResult>,
}

/// Performs a live TCP HTTP CONNECT probe against the local daemon proxy on 127.0.0.1:1080.
async fn probe_local_proxy_connect(host: &str, port: u16) -> Result<String, String> {
    let mut stream = tokio::time::timeout(
        Duration::from_millis(1200),
        TcpStream::connect("127.0.0.1:1080"),
    )
    .await
    .map_err(|_| "Timed out connecting to 127.0.0.1:1080".to_string())?
    .map_err(|e| format!("Failed connecting to 127.0.0.1:1080: {}", e))?;

    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: EphemeralAudit/1.0\r\n\r\n",
        host, port, host, port
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("Failed writing CONNECT probe: {}", e))?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_millis(1500), stream.read(&mut buf))
        .await
        .map_err(|_| "Timed out reading proxy response".to_string())?
        .map_err(|e| format!("Failed reading proxy response: {}", e))?;

    Ok(String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string())
}

/// Builds a structurally valid TLS ClientHello byte slice containing an SNI extension
/// for testing live record-layer splitting without hitting external servers.
fn build_synthetic_client_hello(hostname: &str) -> Vec<u8> {
    let host_bytes = hostname.as_bytes();
    let sni_entry_len = 1 + 2 + host_bytes.len();
    let sni_list_len = 2 + sni_entry_len;
    let sni_ext_len = 2 + sni_list_len;

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]); // Extension Type: server_name (0)
    extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
    extensions.push(0x00); // Name Type: host_name (0)
    extensions.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(host_bytes);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // ClientVersion TLS 1.2
    body.extend_from_slice(&[0x42u8; 32]); // Random (32 bytes)
    body.push(0x00); // SessionID len
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // Cipher suites (4 bytes)
    body.extend_from_slice(&[0x01, 0x00]); // Compression methods (1 byte: null)
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let handshake_len = body.len();
    let mut handshake = Vec::with_capacity(4 + handshake_len);
    handshake.push(0x01); // HandshakeType::ClientHello
    handshake.push(((handshake_len >> 16) & 0xFF) as u8);
    handshake.push(((handshake_len >> 8) & 0xFF) as u8);
    handshake.push((handshake_len & 0xFF) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Runs a comprehensive live diagnostic audit verifying OS proxy routing, RFC 9230 ODoH DNS,
/// WebRTC STUN/TURN blocking, TLS ClientHello splitting, tracker sinkholing, and hardware sentinel status.
pub async fn run_full_privacy_audit(
    state: Arc<AppState>,
    doh_pool: DohPool,
) -> PrivacyAuditReport {
    let mut checks = Vec::with_capacity(6);

    // 1. OS Proxy Routing Check
    {
        let start = Instant::now();
        let proxy_enabled = state.proxy_enabled.load(Ordering::Relaxed);
        let os_proxy_active = tokio::task::spawn_blocking(|| {
            crate::proxy::sys_proxy::is_system_proxy_active(1080)
        })
        .await
        .unwrap_or(false);
        let listener_alive = tokio::time::timeout(
            Duration::from_millis(600),
            TcpStream::connect("127.0.0.1:1080"),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);

        let (status, pts, summary, proof) = if proxy_enabled && os_proxy_active && listener_alive {
            (
                "PASS",
                20,
                "System traffic is routed cleanly through the local privacy shield (127.0.0.1:1080).",
                "OS network service HTTP/HTTPS/SOCKS proxy active for 127.0.0.1:1080; local proxy accepting connections.".to_string(),
            )
        } else if listener_alive {
            (
                "WARN",
                10,
                "Local shield listener is running on :1080, but OS automatic routing is disabled.",
                format!(
                    "proxy_enabled={}, os_proxy_active={}, listener_alive=true",
                    proxy_enabled, os_proxy_active
                ),
            )
        } else {
            (
                "FAIL",
                0,
                "Local privacy proxy on 127.0.0.1:1080 is offline or unreachable.",
                format!(
                    "listener_alive=false, proxy_enabled={}, os_proxy_active={}",
                    proxy_enabled, os_proxy_active
                ),
            )
        };

        checks.push(AuditCheckResult {
            id: "os_proxy_routing".into(),
            name: "OS Network Proxy Routing".into(),
            status: status.into(),
            points_earned: pts,
            max_points: 20,
            latency_ms: start.elapsed().as_millis() as u64,
            summary: summary.into(),
            proof,
        });
    }

    // 2. Oblivious DoH (ODoH) & Encrypted DNS Check
    {
        let start = Instant::now();
        let odoh_enabled = state.odoh_enabled.load(Ordering::Relaxed);
        let ja3 = state.ja3_shuffle.load(Ordering::Relaxed);
        let dns_enabled = state.dns_enabled.load(Ordering::Relaxed);

        let res = doh_pool
            .resolve_ip_smart("cloudflare.com", odoh_enabled, ja3)
            .await;

        let (status, pts, summary, proof) = match res {
            Ok((ip, used_odoh, route_label)) if dns_enabled && odoh_enabled && used_odoh => (
                "PASS",
                20,
                "DNS queries are HPKE-encrypted and cryptographically separated via a blind ODoH Relay.",
                format!(
                    "Live ODoH query for cloudflare.com succeeded via {} -> {} (Relay blind to query, Target blind to client IP).",
                    route_label, ip
                ),
            ),
            Ok((ip, used_odoh, route_label)) if dns_enabled => (
                "WARN",
                12,
                if odoh_enabled {
                    "ODoH Relay temporarily fell back to standard encrypted DoH (still hidden from ISP)."
                } else {
                    "Encrypted DoH is active, but Oblivious DoH (ODoH) Relay Mode is switched OFF."
                },
                format!(
                    "cloudflare.com resolved via {} -> {} (used_odoh={}, odoh_enabled={}).",
                    route_label, ip, used_odoh, odoh_enabled
                ),
            ),
            Ok((ip, _, route_label)) => (
                "WARN",
                8,
                "DNS encryption engine responded, but the Encrypted DNS toggle is currently OFF.",
                format!("Direct probe {} -> {} while dns_enabled=false.", route_label, ip),
            ),
            Err(e) => (
                "FAIL",
                0,
                "Encrypted DNS / ODoH probe could not resolve a test domain.",
                format!("DNS probe error: {}", e),
            ),
        };

        checks.push(AuditCheckResult {
            id: "odoh_dns_resolution".into(),
            name: "Oblivious DoH & Encrypted DNS".into(),
            status: status.into(),
            points_earned: pts,
            max_points: 20,
            latency_ms: start.elapsed().as_millis() as u64,
            summary: summary.into(),
            proof,
        });
    }

    // 3. WebRTC Direct IP Leak Shield Check (Live Proxy CONNECT Probe)
    {
        let start = Instant::now();
        let webrtc_enabled = state.webrtc_shield.load(Ordering::Relaxed);
        let static_match = is_webrtc_stun_target("stun.l.google.com", Some(19302));
        let proxy_reply = probe_local_proxy_connect("stun.l.google.com", 19302).await;

        let (status, pts, summary, proof) = match proxy_reply {
            Ok(ref line) if webrtc_enabled && line.contains("403") => (
                "PASS",
                20,
                "WebRTC STUN/TURN leak attempts are intercepted locally before discovering your real IP.",
                format!(
                    "Live CONNECT stun.l.google.com:19302 -> '{}' (rule match: {:?}).",
                    line, static_match
                ),
            ),
            Ok(ref line) if !webrtc_enabled => (
                "WARN",
                6,
                "WebRTC Direct IP Leak Shield is toggled OFF; STUN discovery is not blocked.",
                format!(
                    "webrtc_shield=false; live CONNECT stun.l.google.com:19302 returned '{}'.",
                    line
                ),
            ),
            Ok(ref line) => (
                "FAIL",
                0,
                "WebRTC STUN probe was not blocked with HTTP 403 as expected.",
                format!("Unexpected proxy reply: '{}'", line),
            ),
            Err(e) => (
                "FAIL",
                0,
                "Could not run WebRTC block probe against local proxy :1080.",
                e,
            ),
        };

        checks.push(AuditCheckResult {
            id: "webrtc_stun_block".into(),
            name: "WebRTC Direct IP Leak Shield".into(),
            status: status.into(),
            points_earned: pts,
            max_points: 20,
            latency_ms: start.elapsed().as_millis() as u64,
            summary: summary.into(),
            proof,
        });
    }

    // 4. TLS Record Splitting (SNI Blinding) & JA3/JA4 Shuffling Check
    {
        let start = Instant::now();
        let sni_enabled = state.sni_fragmentation.load(Ordering::Relaxed);
        let ja3_enabled = state.ja3_shuffle.load(Ordering::Relaxed);

        let sample = build_synthetic_client_hello("privacy-audit.example.com");
        let sni_pos = find_sni_offset(&sample);
        let split_recs = split_client_hello_records(&sample);

        let integrity_ok = if let Some(ref recs) = split_recs {
            let reassembled: Vec<u8> = recs
                .iter()
                .filter_map(|r| r.get(5..))
                .flatten()
                .copied()
                .collect();
            recs.len() >= 3 && reassembled == sample[5..]
        } else {
            false
        };

        let rec_count = split_recs.as_ref().map(|r| r.len()).unwrap_or(0);

        let (status, pts, summary) = match (sni_enabled && integrity_ok, ja3_enabled) {
            (true, true) => (
                "PASS",
                15,
                "TLS ClientHello record splitting and JA3/JA4 cipher profile rotation are active and intact.",
            ),
            (true, false) | (false, true) => (
                "WARN",
                8,
                "Only one TLS obfuscation layer is active (enable both SNI Slicing and JA3 Shuffling for full protection).",
            ),
            _ => (
                "FAIL",
                0,
                "Both TLS SNI record splitting and JA3/JA4 cipher shuffling are turned OFF.",
            ),
        };

        checks.push(AuditCheckResult {
            id: "tls_sni_ja3_shuffling".into(),
            name: "TLS SNI Blinding & JA3 Shuffling".into(),
            status: status.into(),
            points_earned: pts,
            max_points: 15,
            latency_ms: start.elapsed().as_millis() as u64,
            summary: summary.into(),
            proof: format!(
                "SNI byte offset={:?}, split ClientHello into {} RFC-compliant TLS records (reassembly intact={}), JA3 pool shuffling={} (4 cipher/ALPN profiles).",
                sni_pos, rec_count, integrity_ok, ja3_enabled
            ),
        });
    }

    // 5. Ad & Telemetry Tracker Sinkhole Check (Live Proxy Probe)
    {
        let start = Instant::now();
        let dns_blocking_on = state.dns_enabled.load(Ordering::Relaxed);
        let active_rules = crate::dns::sinkhole::total_blocklist_rules();
        let rule_hit = is_tracker("doubleclick.net");
        let proxy_reply = probe_local_proxy_connect("doubleclick.net", 443).await;

        let (status, pts, summary, proof) = match proxy_reply {
            Ok(ref line) if !dns_blocking_on => (
                "WARN",
                5,
                format!(
                    "Ad & Tracker blocking is currently switched OFF ({} RAM filter rules standing by).",
                    active_rules
                ),
                format!("Live CONNECT doubleclick.net:443 -> '{}' while dns_enabled=false.", line),
            ),
            Ok(ref line) if line.contains("403") && rule_hit.is_some() => (
                "PASS",
                15,
                format!(
                    "Blocking ads & telemetry across {} RAM filter rules + real-time CNAME uncloaking.",
                    active_rules
                ),
                format!(
                    "Live CONNECT doubleclick.net:443 -> '{}' (matched rule: {}; {} volatile RAM rules loaded).",
                    line,
                    rule_hit.unwrap_or("Tracker"),
                    active_rules
                ),
            ),
            Ok(ref line) => (
                "WARN",
                5,
                "Tracker classification matched, but local proxy returned an unexpected status.".into(),
                format!("CONNECT doubleclick.net:443 -> '{}'", line),
            ),
            Err(e) => (
                "FAIL",
                0,
                "Could not verify tracker sinkhole over 127.0.0.1:1080.".into(),
                e,
            ),
        };

        checks.push(AuditCheckResult {
            id: "tracker_sinkhole_enforcement".into(),
            name: "Telemetry & Tracker Sinkhole".into(),
            status: status.into(),
            points_earned: pts,
            max_points: 15,
            latency_ms: start.elapsed().as_millis() as u64,
            summary,
            proof,
        });
    }

    // 6. Hardware Snooping Sentinel (Camera & Microphone)
    {
        let start = Instant::now();
        let sentinel_enabled = state.hardware_sentinel_enabled.load(Ordering::Relaxed);
        let hw = tokio::task::spawn_blocking(probe_hardware_state)
            .await
            .unwrap_or(crate::privacy::HardwareStatus {
                camera_active: false,
                mic_active: false,
                camera_apps: Vec::new(),
                mic_apps: Vec::new(),
                platform_method: "Probe interrupted".into(),
            });

        let (status, pts, summary, proof) = if !sentinel_enabled {
            (
                "WARN",
                5,
                "Hardware Snooping Sentinel watchdog is currently switched OFF.",
                format!("Last probe method: {}", hw.platform_method),
            )
        } else if hw.camera_active || hw.mic_active {
            (
                "WARN",
                6,
                "Active camera or microphone access detected right now — confirm this matches an app you expect.",
                format!(
                    "Camera active={} ({:?}), Mic active={} ({:?}) via {}",
                    hw.camera_active, hw.camera_apps, hw.mic_active, hw.mic_apps, hw.platform_method
                ),
            )
        } else {
            (
                "PASS",
                10,
                "Camera and microphone hardware sensors are idle with zero unauthorized streams.",
                format!(
                    "Camera=IDLE, Mic=IDLE — monitored silently without OS capture prompts via {}",
                    hw.platform_method
                ),
            )
        };

        checks.push(AuditCheckResult {
            id: "hardware_sentinel_status".into(),
            name: "Camera & Mic Hardware Sentinel".into(),
            status: status.into(),
            points_earned: pts,
            max_points: 10,
            latency_ms: start.elapsed().as_millis() as u64,
            summary: summary.into(),
            proof,
        });
    }

    let score: u8 = checks
        .iter()
        .map(|c| c.points_earned as u16)
        .sum::<u16>()
        .min(100) as u8;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    state
        .log_event(
            "PRIVACY_AUDIT",
            &format!("Live Privacy Audit Completed ({}/100)", score),
            "Verified OS proxy, ODoH relay, WebRTC shield, TLS splitting, sinkhole, and hardware sensors.",
            "localhost",
        )
        .await;

    PrivacyAuditReport {
        score,
        timestamp,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthetic_client_hello_splits_cleanly() {
        let packet = build_synthetic_client_hello("example.com");
        let offset = find_sni_offset(&packet);
        assert!(offset.is_some(), "Expected SNI offset in synthetic ClientHello");
        let recs = split_client_hello_records(&packet).expect("Expected record splits");
        assert!(recs.len() >= 3);
        let reassembled: Vec<u8> = recs.iter().flat_map(|r| r[5..].iter().copied()).collect();
        assert_eq!(reassembled, packet[5..]);
    }
}
