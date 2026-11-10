pub mod dpi_bypass;
pub mod sys_proxy;

use crate::decorrelator::DecorrelatorEngine;
use crate::dns::sinkhole::is_tracker;
use crate::proxy::dpi_bypass::send_fragmented_client_hello;
use crate::state::AppState;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct ProxyServer {
    state: Arc<AppState>,
    decorrelator: Arc<DecorrelatorEngine>,
}

impl ProxyServer {
    pub fn new(state: Arc<AppState>, decorrelator: Arc<DecorrelatorEngine>) -> Self {
        Self {
            state,
            decorrelator,
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
            tokio::spawn(async move {
                let _ = handle_client(stream, client_addr, state, decorrelator).await;
            });
        }
    }
}

async fn handle_client(
    mut client_stream: TcpStream,
    _client_addr: SocketAddr,
    state: Arc<AppState>,
    decorrelator: Arc<DecorrelatorEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut initial_buf = [0u8; 4096];
    let n = client_stream.read(&mut initial_buf).await?;
    if n == 0 {
        return Ok(());
    }

    // 1. SOCKS5 HANDSHAKE DETECTION (RFC 1928)
    if initial_buf[0] == 0x05 {
        return handle_socks5(client_stream, &initial_buf[..n], state, decorrelator).await;
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

        // Tracker Check
        if let Some(tracker) = is_tracker(host) {
            state.trackers_blocked.fetch_add(1, Ordering::Relaxed);
            state
                .log_event(
                    "TRACKER_BLOCKED",
                    &format!("Blocked Connection: {}", tracker),
                    &format!("Denied HTTP CONNECT tunnel to {}", target_host_port),
                    host,
                )
                .await;

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

        // Connect to upstream destination
        let mut target_stream = match TcpStream::connect(target_host_port).await {
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

        // Read client's first packet (typically TLS ClientHello)
        let mut first_packet = [0u8; 4096];
        let bytes_read = client_stream.read(&mut first_packet).await?;
        if bytes_read > 0 {
            let use_sni_frag = state.sni_fragmentation.load(Ordering::Relaxed);
            if use_sni_frag {
                let did_frag =
                    send_fragmented_client_hello(&mut target_stream, &first_packet[..bytes_read])
                        .await?;

                if did_frag {
                    state.sni_sliced_handshakes.fetch_add(1, Ordering::Relaxed);
                    state
                        .log_event(
                            "SNI_FRAGMENTED",
                            "Anti-DPI: SNI Packet Sliced",
                            &format!(
                                "Fragmented TLS ClientHello for {} to blind ISP inspection",
                                host
                            ),
                            host,
                        )
                        .await;
                }
            } else {
                target_stream.write_all(&first_packet[..bytes_read]).await?;
                target_stream.flush().await?;
            }
        }

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
        let host_clean = host.split(':').next().unwrap_or(host);

        if let Some(tracker) = is_tracker(host_clean) {
            state.trackers_blocked.fetch_add(1, Ordering::Relaxed);
            state
                .log_event(
                    "TRACKER_BLOCKED",
                    &format!("Blocked Plain HTTP Tracker: {}", tracker),
                    &format!("Blocked plain HTTP request to {}", host_clean),
                    host_clean,
                )
                .await;
            client_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            return Ok(());
        }

        state.queries_intercepted.fetch_add(1, Ordering::Relaxed);
        decorrelator.trigger_chaff_burst("PROXY_HTTP", host_clean);
        state
            .log_event(
                "PROXY_INTERCEPTED",
                "HTTP Request Intercepted",
                &format!("Forwarded HTTP request for {}", host_clean),
                host_clean,
            )
            .await;

        let target_addr = if host.contains(':') {
            host.to_string()
        } else {
            format!("{}:80", host)
        };

        if let Ok(mut target_stream) = TcpStream::connect(&target_addr).await {
            target_stream.write_all(&initial_buf[..n]).await?;
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
    if req_len < 7 || req_buf[0] != 0x05 || req_buf[1] != 0x01 {
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

    // Tracker Check
    if let Some(tracker) = is_tracker(&target_host) {
        state.trackers_blocked.fetch_add(1, Ordering::Relaxed);
        state
            .log_event(
                "TRACKER_BLOCKED",
                &format!("SOCKS5 Blocked Tracker: {}", tracker),
                &format!("Blocked SOCKS5 connection to {}:{}", target_host, target_port),
                &target_host,
            )
            .await;
        // Reply Connection not allowed by ruleset (0x02)
        let _ = client_stream.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Ok(());
    }

    // Connect to destination
    let target_addr = format!("{}:{}", target_host, target_port);
    let mut target_stream = match TcpStream::connect(&target_addr).await {
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

    // Read first client packet (typically TLS ClientHello for HTTPS)
    let mut first_packet = [0u8; 4096];
    let bytes_read = client_stream.read(&mut first_packet).await?;
    if bytes_read > 0 {
        let use_sni_frag = state.sni_fragmentation.load(Ordering::Relaxed);
        if use_sni_frag && target_port == 443 {
            let did_frag =
                send_fragmented_client_hello(&mut target_stream, &first_packet[..bytes_read])
                    .await?;

            if did_frag {
                state.sni_sliced_handshakes.fetch_add(1, Ordering::Relaxed);
                state
                    .log_event(
                        "SNI_FRAGMENTED",
                        "Anti-DPI: SNI Packet Sliced",
                        &format!(
                            "Fragmented SOCKS5 TLS ClientHello for {} to blind ISP inspection",
                            target_host
                        ),
                        &target_host,
                    )
                    .await;
            }
        } else {
            target_stream.write_all(&first_packet[..bytes_read]).await?;
            target_stream.flush().await?;
        }
    }

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
