pub mod dpi_bypass;
pub mod fingerprint;
pub mod sys_proxy;
pub mod webrtc_shield;

use crate::decorrelator::DecorrelatorEngine;
use crate::dns::doh_pool::DohPool;
use crate::dns::sinkhole::is_tracker;
use crate::proxy::dpi_bypass::send_obfuscated_client_hello;
use crate::proxy::fingerprint::normalize_http_request_headers;
use crate::proxy::webrtc_shield::is_webrtc_stun_target;
use crate::state::AppState;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

    if let Some(tracker) = is_tracker(host) {
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

    // 1. Attempt Encrypted ODoH Relay / DoH Resolution to blind ISP from plaintext DNS
    if let Ok((ip, used_odoh, route_name)) = doh_pool.resolve_ip_smart(host, use_odoh, ja3_shuffle).await {
        let addr = SocketAddr::new(ip, port);
        if let Ok(s) = TcpStream::connect(addr).await {
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
                        &format!("Blinded ISP: Resolved {} -> {} via {}", host, ip, route_name),
                        host,
                    )
                    .await;
            }
            return Ok(s);
        }
    }

    // 2. Fallback to standard connection if DoH failed or for internal hostnames
    let target = format!("{}:{}", host, port);
    TcpStream::connect(&target).await
}

async fn forward_tls_initial_flight(
    client_stream: &mut TcpStream,
    target_stream: &mut TcpStream,
    host: &str,
    port: u16,
    state: &AppState,
) -> std::io::Result<()> {
    let mut first_packet = [0u8; 4096];
    let bytes_read = client_stream.read(&mut first_packet).await?;
    if bytes_read == 0 {
        return Ok(());
    }

    let use_sni_frag = state.sni_fragmentation.load(Ordering::Relaxed);
    let use_record_split = state.ja3_shuffle.load(Ordering::Relaxed) && port == 443;

    if use_sni_frag || use_record_split {
        let (did_obfuscate, did_record_split) = send_obfuscated_client_hello(
            target_stream,
            &first_packet[..bytes_read],
            use_record_split,
            use_sni_frag,
        )
        .await?;

        if did_obfuscate {
            state.sni_sliced_handshakes.fetch_add(1, Ordering::Relaxed);
            if did_record_split {
                state.ja3_fingerprints_shuffled.fetch_add(1, Ordering::Relaxed);
                state
                    .log_event(
                        "SNI_FRAGMENTED",
                        "Anti-DPI & Record Split Applied",
                        &format!("Multi-record split TLS ClientHello for {} to blind ISP & passive JA3 DPI", host),
                        host,
                    )
                    .await;
            } else {
                state
                    .log_event(
                        "SNI_FRAGMENTED",
                        "Anti-DPI: SNI Packet Sliced",
                        &format!("Fragmented TLS ClientHello for {} to blind ISP inspection", host),
                        host,
                    )
                    .await;
            }
            return Ok(());
        }
    }

    target_stream.write_all(&first_packet[..bytes_read]).await?;
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
        let host = target_host_port.split(':').next().unwrap_or(target_host_port);
        let port: u16 = target_host_port
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);

        // Tracker & WebRTC STUN/TURN Policy Check
        if check_policy_block(host, port, "HTTP", &state).await {
            client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }

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

        let mut target_stream = match connect_with_doh(host, port, &doh_pool, &state).await {
            Ok(s) => s,
            Err(e) => {
                client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                return Err(Box::new(e));
            }
        };

        // Notify client tunnel established
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Forward initial TLS flight with SNI/Record obfuscation
        forward_tls_initial_flight(&mut client_stream, &mut target_stream, host, port, &state)
            .await?;

        // Stream remaining bidirectional TCP traffic
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
        return Ok(());
    }

    // 3. PLAIN HTTP FORWARD PROXY (GET / POST / etc.)
    if let Some(host_line) = request_head.lines().find(|l| l.to_ascii_lowercase().starts_with("host:")) {
        let host = host_line["host:".len()..].trim();
        let (host_str, port) = if let Some((h, p)) = host.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(80))
        } else {
            (host, 80)
        };

        if check_policy_block(host_str, port, "HTTP", &state).await {
            client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }

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

        if let Ok(mut target_stream) = connect_with_doh(host_str, port, &doh_pool, &state).await {
            let payload_to_send = if state.ja3_shuffle.load(Ordering::Relaxed) {
                if let Some(norm) = normalize_http_request_headers(&initial_buf[..n]) {
                    state.ja3_fingerprints_shuffled.fetch_add(1, Ordering::Relaxed);
                    norm
                } else {
                    initial_buf[..n].to_vec()
                }
            } else {
                initial_buf[..n].to_vec()
            };

            target_stream.write_all(&payload_to_send).await?;
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

    // Connect to destination via encrypted DoH
    let mut target_stream = match connect_with_doh(&target_host, target_port, &doh_pool, &state).await {
        Ok(s) => s,
        Err(e) => {
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
    Ok(())
}
