pub mod dpi_bypass;
pub mod fingerprint;
pub mod sys_proxy;
pub mod webrtc_shield;

use crate::decorrelator::DecorrelatorEngine;
use crate::dns::doh_pool::DohPool;
use crate::dns::sinkhole::match_tracker;
use crate::proxy::dpi_bypass::send_obfuscated_client_hello;
use crate::proxy::fingerprint::rewrite_http_proxy_head;
use crate::proxy::webrtc_shield::is_webrtc_stun_target;
use crate::state::AppState;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

fn parse_host_port(authority: &str, default_port: u16) -> (&str, u16) {
    let trimmed = authority.trim();
    if let Some(after_open) = trimmed.strip_prefix('[') {
        if let Some((ip_part, rest)) = after_open.split_once(']') {
            if let Some(port_str) = rest.strip_prefix(':') {
                return (ip_part, port_str.parse::<u16>().unwrap_or(default_port));
            }
            return (ip_part, default_port);
        }
    }
    if let Some((host, port_str)) = trimmed.rsplit_once(':') {
        if !host.contains(':') {
            return (host, port_str.parse::<u16>().unwrap_or(default_port));
        }
    }
    (trimmed, default_port)
}

async fn relay_bidirectional(client_stream: TcpStream, target_stream: TcpStream) {
    let (mut cr, mut cw) = client_stream.into_split();
    let (mut tr, mut tw) = target_stream.into_split();

    let client_to_target = async {
        let _ = tokio::io::copy(&mut cr, &mut tw).await;
        let _ = tw.shutdown().await;
    };

    let target_to_client = async {
        let _ = tokio::io::copy(&mut tr, &mut cw).await;
        let _ = cw.shutdown().await;
    };

    tokio::join!(client_to_target, target_to_client);
}

pub struct ProxyServer {
    state: Arc<AppState>,
    decorrelator: Arc<DecorrelatorEngine>,
    doh_pool: DohPool,
}

impl ProxyServer {
    pub fn new(
        state: Arc<AppState>,
        decorrelator: Arc<DecorrelatorEngine>,
        doh_pool: DohPool,
    ) -> Self {
        Self {
            state,
            decorrelator,
            doh_pool,
        }
    }

    pub async fn run(&self, bind_addr: SocketAddr) -> Result<(), String> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind Proxy TCP server on {}: {}", bind_addr, e))?;

        println!("[PROXY] Listening on {}", bind_addr);

        loop {
            let (stream, client_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Proxy accept error: {}", e);
                    continue;
                }
            };

            let state = self.state.clone();
            let decorrelator = self.decorrelator.clone();
            let doh_pool = self.doh_pool.clone();
            tokio::spawn(async move {
                let _ = handle_client(stream, client_addr, state, decorrelator, doh_pool).await;
            });
        }
    }
}

async fn check_policy_block(host: &str, port: u16, proto: &str, state: &AppState) -> bool {
    if state.webrtc_shield.load(Ordering::Relaxed) {
        if let Some(reason) = is_webrtc_stun_target(host, Some(port)) {
            state.webrtc_leaks_blocked.fetch_add(1, Ordering::Relaxed);
            state
                .log_event(
                    "WEBRTC_BLOCKED",
                    &format!("{} WebRTC IP Leak Blocked", proto),
                    &format!("Dropped {}:{} ({}) to hide LAN/WAN IP", host, port, reason),
                    host,
                )
                .await;
            return true;
        }
    }

    if state.dns_enabled.load(Ordering::Relaxed) {
        if let Some(tracker) = match_tracker(host) {
            state.trackers_blocked.fetch_add(1, Ordering::Relaxed);
            state
                .log_event(
                    "TRACKER_BLOCKED",
                    &format!("{} Blocked Tracker: {}", proto, tracker),
                    &format!("Denied connection to {}:{}", host, port),
                    host,
                )
                .await;
            return true;
        }
    }

    false
}

async fn connect_with_doh(
    host: &str,
    port: u16,
    doh_pool: &DohPool,
    state: &AppState,
) -> Result<TcpStream, std::io::Error> {
    let use_odoh = state.odoh_enabled.load(Ordering::Relaxed);
    let ja3_shuffle = state.ja3_shuffle.load(Ordering::Relaxed);
    let block_trackers = state.dns_enabled.load(Ordering::Relaxed);

    // 1. Encrypted ODoH Relay / DoH Resolution (A + fallback AAAA) with CNAME Uncloaking
    match doh_pool
        .resolve_ips_verified(host, use_odoh, ja3_shuffle, block_trackers)
        .await
    {
        Ok((ips, used_odoh, route_name)) => {
            state
                .odoh_fallback_active
                .store(use_odoh && !used_odoh, Ordering::Relaxed);

            let mut last_conn_err: Option<std::io::Error> = None;
            for ip in ips.into_iter().take(4) {
                let addr = SocketAddr::new(ip, port);
                match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                    Ok(Ok(s)) => {
                        if used_odoh {
                            state.odoh_queries_relayed.fetch_add(1, Ordering::Relaxed);
                            state
                                .log_event(
                                    "ODOH_RESOLVED",
                                    "Oblivious DoH (ODoH) Relayed",
                                    &format!("Resolved {} -> {} via {}", host, ip, route_name),
                                    host,
                                )
                                .await;
                        } else {
                            state
                                .log_event(
                                    "DOH_RESOLVED",
                                    "Encrypted DoH Resolution",
                                    &format!(
                                        "Blinded ISP: Resolved {} -> {} via {}",
                                        host, ip, route_name
                                    ),
                                    host,
                                )
                                .await;
                        }
                        return Ok(s);
                    }
                    Ok(Err(e)) => last_conn_err = Some(e),
                    Err(_) => {
                        last_conn_err = Some(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("TCP connect timed out for {}:{}", ip, port),
                        ));
                    }
                }
            }
            return Err(last_conn_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::HostUnreachable, "No reachable IPs")
            }));
        }
        Err(crate::dns::doh_pool::ResolveError::CnameCloakedTracker {
            original_domain,
            canonical_target,
            matched_tracker,
        }) => {
            state.trackers_blocked.fetch_add(1, Ordering::Relaxed);
            state
                .log_event(
                    "TRACKER_BLOCKED",
                    "Blocked Cloaked CNAME Tracker",
                    &format!(
                        "Unmasked '{}' -> '{}' (rule: {}) before TCP connect",
                        original_domain,
                        canonical_target.as_deref().unwrap_or(""),
                        matched_tracker
                    ),
                    &original_domain,
                )
                .await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Blocked CNAME cloaked tracker: {}", matched_tracker),
            ));
        }
        Err(crate::dns::doh_pool::ResolveError::Failed(reason)) => {
            // Only fall back to OS resolver for local/intranet names or if all DNS privacy is off
            let is_local_name = host.eq_ignore_ascii_case("localhost")
                || host.to_ascii_lowercase().ends_with(".local")
                || !host.contains('.');
            if !is_local_name && (use_odoh || block_trackers) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable,
                    format!("Encrypted DNS failed (refusing plaintext OS fallback): {}", reason),
                ));
            }
        }
    }

    // 2. Local hostname fallback (or when encrypted resolution + blocking are turned off)
    let target = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&target))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Connect timed out"))?
}

/// Inspects initial tunnel traffic without deadlocking server-speaks-first protocols (SMTP/SSH/IMAP)
/// and buffers split TLS ClientHello records cleanly before applying SNI blinding.
async fn forward_tls_initial_flight(
    client_stream: &mut TcpStream,
    target_stream: &mut TcpStream,
    host: &str,
    port: u16,
    state: &AppState,
) -> std::io::Result<()> {
    let mut client_buf = Vec::with_capacity(8192);
    let mut c_chunk = [0u8; 4096];
    let mut s_chunk = [0u8; 4096];

    tokio::select! {
        res = client_stream.read(&mut c_chunk) => {
            let n = res?;
            if n == 0 {
                return Ok(());
            }
            client_buf.extend_from_slice(&c_chunk[..n]);
        }
        res = target_stream.read(&mut s_chunk) => {
            let n = res?;
            if n == 0 {
                return Ok(());
            }
            // Server-speaks-first protocol (e.g. SMTP banner, SSH greeting): relay immediately and hand off
            client_stream.write_all(&s_chunk[..n]).await?;
            client_stream.flush().await?;
            return Ok(());
        }
    }

    let use_sni_frag = state.sni_fragmentation.load(Ordering::Relaxed);

    if use_sni_frag && client_buf.len() >= 5 && client_buf[0] == 0x16 {
        // Buffer remainder of split TLS ClientHello record up to 16 KB (within 60ms)
        let rec_len = u16::from_be_bytes([client_buf[3], client_buf[4]]) as usize;
        let expected_total = (5 + rec_len).min(16384);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(60);

        while client_buf.len() < expected_total {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            match tokio::time::timeout(deadline - now, client_stream.read(&mut c_chunk)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(more)) => client_buf.extend_from_slice(&c_chunk[..more]),
                Ok(Err(e)) => return Err(e),
            }
        }

        let use_record_split = port == 443;
        let (did_obfuscate, did_record_split) = send_obfuscated_client_hello(
            target_stream,
            &client_buf,
            use_record_split,
            use_sni_frag,
        )
        .await?;

        if did_obfuscate {
            state.sni_sliced_handshakes.fetch_add(1, Ordering::Relaxed);
            state
                .log_event(
                    "SNI_FRAGMENTED",
                    if did_record_split {
                        "Anti-DPI: Multi-Record SNI Split"
                    } else {
                        "Anti-DPI: SNI TCP Fragmented"
                    },
                    &format!(
                        "Split TLS ClientHello for {} against single-packet DPI",
                        host
                    ),
                    host,
                )
                .await;
            return Ok(());
        }
    }

    target_stream.write_all(&client_buf).await?;
    target_stream.flush().await?;
    Ok(())
}

async fn handle_client(
    mut client_stream: TcpStream,
    _client_addr: SocketAddr,
    state: Arc<AppState>,
    decorrelator: Arc<DecorrelatorEngine>,
    doh_pool: DohPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut initial_buf = [0u8; 4096];
    let n = client_stream.read(&mut initial_buf).await?;
    if n == 0 {
        return Ok(());
    }

    // 1. SOCKS5 HANDSHAKE DETECTION (RFC 1928)
    if initial_buf[0] == 0x05 {
        return handle_socks5(client_stream, &initial_buf[..n], state, decorrelator, doh_pool).await;
    }

    let request_head = String::from_utf8_lossy(&initial_buf[..n]);

    // 2. HTTP CONNECT (HTTPS Tunneling)
    if request_head.starts_with("CONNECT ") {
        let first_line = request_head.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(());
        }

        let target_host_port = parts[1];
        let (host, port) = parse_host_port(target_host_port, 443);

        // Tracker & WebRTC STUN/TURN Policy Check
        if check_policy_block(host, port, "HTTP", &state).await {
            client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }

        let mut target_stream = match connect_with_doh(host, port, &doh_pool, &state).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                return Ok(());
            }
            Err(e) => {
                eprintln!("[PROXY] HTTP CONNECT {}:{} -> 502 ({})", host, port, e);
                client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                return Err(Box::new(e));
            }
        };

        // Legitimate Connection: Increment metric & Trigger Chaff Decoys!
        state.queries_intercepted.fetch_add(1, Ordering::Relaxed);
        decorrelator.trigger_chaff_burst("PROXY_HTTP_CONNECT", host);
        state
            .log_event(
                "PROXY_INTERCEPTED",
                "HTTPS Connection Intercepted",
                &format!("Tunneling traffic to {}", target_host_port),
                host,
            )
            .await;

        // Notify client tunnel established
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Forward initial TLS flight with SNI/Record obfuscation (or server-speaks-first banner)
        forward_tls_initial_flight(&mut client_stream, &mut target_stream, host, port, &state)
            .await?;

        // Stream remaining bidirectional TCP traffic
        relay_bidirectional(client_stream, target_stream).await;
        return Ok(());
    }

    // 3. PLAIN HTTP FORWARD PROXY (GET / POST / etc.)
    if let Some(host_line) = request_head.lines().find(|l| l.to_ascii_lowercase().starts_with("host:")) {
        let host = host_line["host:".len()..].trim();
        let (host_str, port) = parse_host_port(host, 80);

        if check_policy_block(host_str, port, "HTTP", &state).await {
            client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }

        match connect_with_doh(host_str, port, &doh_pool, &state).await {
            Ok(mut target_stream) => {
                state.queries_intercepted.fetch_add(1, Ordering::Relaxed);
                decorrelator.trigger_chaff_burst("PROXY_HTTP", host_str);
                state
                    .log_event(
                        "PROXY_INTERCEPTED",
                        "HTTP Request Intercepted",
                        &format!("Forwarded HTTP request for {}", host_str),
                        host_str,
                    )
                    .await;

                let normalize_identity = state.ja3_shuffle.load(Ordering::Relaxed);
                let payload_to_send = rewrite_http_proxy_head(&initial_buf[..n], normalize_identity)
                    .unwrap_or_else(|| initial_buf[..n].to_vec());
                if normalize_identity {
                    state.ja3_fingerprints_shuffled.fetch_add(1, Ordering::Relaxed);
                }

                target_stream.write_all(&payload_to_send).await?;
                target_stream.flush().await?;

                let (mut cr, mut cw) = client_stream.into_split();
                let (mut tr, mut tw) = target_stream.into_split();

                let client_to_target = async {
                    let _ = tokio::io::copy(&mut cr, &mut tw).await;
                    let _ = tw.shutdown().await;
                };

                let target_to_client = async {
                    let _ = tokio::io::copy(&mut tr, &mut cw).await;
                    let _ = cw.shutdown().await;
                };

                // Enforce single-request policy boundary: end tunnel as soon as origin finishes its response
                tokio::pin!(target_to_client);
                tokio::pin!(client_to_target);
                tokio::select! {
                    _ = &mut target_to_client => {}
                    _ = &mut client_to_target => {
                        let _ = target_to_client.await;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                client_stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await?;
            }
            Err(_) => {
                client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await?;
            }
        }
    }

    Ok(())
}

async fn handle_socks5(
    mut client_stream: TcpStream,
    initial_buf: &[u8],
    state: Arc<AppState>,
    decorrelator: Arc<DecorrelatorEngine>,
    doh_pool: DohPool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // SOCKS5 Greeting: client sent [0x05, nmethods, ...methods]
    if initial_buf.len() < 2 || initial_buf[0] != 0x05 {
        return Ok(());
    }

    // Server selects Method 0x00 (NO AUTHENTICATION REQUIRED)
    client_stream.write_all(&[0x05, 0x00]).await?;

    // Read SOCKS5 Request
    let mut req_buf = [0u8; 512];
    let req_len = client_stream.read(&mut req_buf).await?;
    if req_len < 7 || req_buf[0] != 0x05 {
        return Ok(());
    }

    // Intercept SOCKS5 UDP ASSOCIATE (0x03) used for direct WebRTC/UDP hole punching when shield is active
    if req_buf[1] == 0x03 && state.webrtc_shield.load(Ordering::Relaxed) {
        state.webrtc_leaks_blocked.fetch_add(1, Ordering::Relaxed);
        state
            .log_event(
                "WEBRTC_BLOCKED",
                "SOCKS5 UDP Associate Blocked",
                "Prevented direct UDP socket binding commonly used by WebRTC STUN leak probes",
                "0.0.0.0",
            )
            .await;
        let _ = client_stream.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Ok(());
    }

    if req_buf[1] != 0x01 {
        // CMD != 0x01 (CONNECT) -> command not supported
        let _ = client_stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Ok(());
    }

    let atyp = req_buf[3];
    let (target_host, target_port) = match atyp {
        0x01 => {
            // IPv4 (4 bytes)
            let ip = std::net::Ipv4Addr::new(req_buf[4], req_buf[5], req_buf[6], req_buf[7]);
            let port = u16::from_be_bytes([req_buf[8], req_buf[9]]);
            (ip.to_string(), port)
        }
        0x03 => {
            // Domain name: 1 byte len + domain bytes
            let dlen = req_buf[4] as usize;
            if req_len < 5 + dlen + 2 {
                return Ok(());
            }
            let domain = String::from_utf8_lossy(&req_buf[5..5 + dlen]).to_string();
            let port = u16::from_be_bytes([req_buf[5 + dlen], req_buf[6 + dlen]]);
            (domain, port)
        }
        0x04 => {
            // IPv6 (16 bytes)
            if req_len < 4 + 16 + 2 {
                return Ok(());
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&req_buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([req_buf[20], req_buf[21]]);
            (ip.to_string(), port)
        }
        _ => return Ok(()),
    };

    // Tracker & WebRTC STUN/TURN Policy Check
    if check_policy_block(&target_host, target_port, "SOCKS5", &state).await {
        // Reply Connection not allowed by ruleset (0x02)
        let _ = client_stream.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Ok(());
    }

    // Connect to destination via encrypted DoH (with real-time CNAME tracker enforcement)
    let mut target_stream = match connect_with_doh(&target_host, target_port, &doh_pool, &state).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Reply Connection not allowed by ruleset (0x02)
            let _ = client_stream.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Ok(());
        }
        Err(e) => {
            eprintln!("[PROXY] SOCKS5 {}:{} -> 0x04 ({})", target_host, target_port, e);
            // Host unreachable (0x04)
            let _ = client_stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(Box::new(e));
        }
    };

    // SOCKS5 SUCCESS Response (0x00)
    client_stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // Record Metrics & Trigger Chaff Decoys!
    state.queries_intercepted.fetch_add(1, Ordering::Relaxed);
    decorrelator.trigger_chaff_burst("SOCKS5", &target_host);
    state
        .log_event(
            "PROXY_INTERCEPTED",
            "SOCKS5 Connection Established",
            &format!("Tunneled SOCKS5 traffic for {}:{}", target_host, target_port),
            &target_host,
        )
        .await;

    // Forward initial TLS flight with SNI/Record obfuscation
    forward_tls_initial_flight(
        &mut client_stream,
        &mut target_stream,
        &target_host,
        target_port,
        &state,
    )
    .await?;

    // Bidirectional TCP forwarding
    relay_bidirectional(client_stream, target_stream).await;
    Ok(())
}

#[cfg(test)]
mod proxy_unit_tests {
    use super::parse_host_port;

    #[test]
    fn test_parse_host_port_ipv4_ipv6_and_domains() {
        assert_eq!(parse_host_port("example.com:8443", 443), ("example.com", 8443));
        assert_eq!(parse_host_port("example.com", 443), ("example.com", 443));
        assert_eq!(parse_host_port("[::1]:59736", 443), ("::1", 59736));
        assert_eq!(parse_host_port("[2606:4700:4700::1111]", 443), ("2606:4700:4700::1111", 443));
    }
}
