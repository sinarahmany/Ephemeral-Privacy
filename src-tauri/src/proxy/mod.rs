pub mod dpi_bypass;
pub mod sys_proxy;

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
}

impl ProxyServer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn run(&self, bind_addr: SocketAddr) -> Result<(), String> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind Proxy TCP server on {}: {}", bind_addr, e))?;

        loop {
            let (stream, client_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Proxy accept error: {}", e);
                    continue;
                }
            };

            let state = self.state.clone();
            tokio::spawn(async move {
                let _ = handle_client(stream, client_addr, state).await;
            });
        }
    }
}

async fn handle_client(
    mut client_stream: TcpStream,
    _client_addr: SocketAddr,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 4096];
    let n = client_stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_head = String::from_utf8_lossy(&buf[..n]);

    // Handle HTTP CONNECT (HTTPS tunneling)
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

        // Read the client's first packet (typically TLS ClientHello)
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
    }

    Ok(())
}
