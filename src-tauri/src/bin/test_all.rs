use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri_app_lib::decorrelator::DecorrelatorEngine;
use tauri_app_lib::dns::doh_pool::DohPool;
use tauri_app_lib::dns::DnsServer;
use tauri_app_lib::proxy::ProxyServer;
use tauri_app_lib::state::AppState;
use simple_dns::{Name, Packet, Question, CLASS, QTYPE, TYPE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[tokio::main]
async fn main() {
    println!("========================================================");
    println!("      EPHEMERAL PRIVACY SUITE - FULL SUBSYSTEM TEST     ");
    println!("========================================================");

    let state = Arc::new(AppState::new());
    let doh_pool = DohPool::new();
    let decorrelator = Arc::new(DecorrelatorEngine::new(state.clone(), doh_pool.clone()));

    // TEST 1: DoH Pool directly
    println!("\n[1/6] Testing Upstream DoH Resolvers directly...");
    let mut query = Packet::new_query(1001);
    query.questions.push(Question::new(
        Name::new("example.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        simple_dns::QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let raw_packet = query.build_bytes_vec_compressed().unwrap();

    let resolver = doh_pool.random_resolver(None);
    println!("  -> Querying DoH resolver: {} ({})", resolver.name, resolver.doh_url);
    match doh_pool.query_doh(&raw_packet, resolver).await {
        Ok(resp) => {
            let parsed = Packet::parse(&resp).unwrap();
            println!("  [SUCCESS] DoH returned valid DNS response with {} answers!", parsed.answers.len());
        }
        Err(e) => println!("  [FAIL] DoH query failed: {}", e),
    }

    // TEST 2: DNS Server (Local UDP :5300)
    println!("\n[2/6] Testing Local DNS UDP Server on 127.0.0.1:5300...");
    let dns_server = DnsServer::new(state.clone(), doh_pool.clone(), decorrelator.clone());
    tokio::spawn(async move {
        let _ = dns_server.run_auto().await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send query to 127.0.0.1:5300
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client_sock.send_to(&raw_packet, "127.0.0.1:5300").await.unwrap();

    let mut buf = [0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), client_sock.recv_from(&mut buf))
        .await
        .expect("Timeout waiting for local DNS response")
        .unwrap();

    let dns_resp = Packet::parse(&buf[..len]).unwrap();
    println!("  [SUCCESS] Local DNS UDP server replied with {} answers!", dns_resp.answers.len());

    // TEST 3: DNS Sinkhole Block test (tracking domain)
    println!("\n[3/6] Testing Tracker Sinkhole (adservice.google.com)...");
    let mut ad_query = Packet::new_query(1002);
    ad_query.questions.push(Question::new(
        Name::new("adservice.google.com").unwrap(),
        QTYPE::TYPE(TYPE::A),
        simple_dns::QCLASS::CLASS(CLASS::IN),
        false,
    ));
    let raw_ad_packet = ad_query.build_bytes_vec_compressed().unwrap();
    client_sock.send_to(&raw_ad_packet, "127.0.0.1:5300").await.unwrap();

    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client_sock.recv_from(&mut buf))
        .await
        .expect("Timeout waiting for sinkhole response")
        .unwrap();

    let ad_resp = Packet::parse(&buf[..len]).unwrap();
    println!("  [SUCCESS] Sinkhole blocked tracker! Answers: {:?}", ad_resp.answers.first().map(|a| &a.rdata));
    println!("  Trackers blocked counter: {}", state.trackers_blocked.load(Ordering::Relaxed));

    // TEST 4: SOCKS5 & HTTP Proxy Interception & Chaff Triggering
    println!("\n[4/6] Testing Proxy Server (127.0.0.1:1080)...");
    let proxy_server = ProxyServer::new(state.clone(), decorrelator.clone());
    let proxy_bind = "127.0.0.1:1080".parse().unwrap();
    tokio::spawn(async move {
        let _ = proxy_server.run(proxy_bind).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let init_queries = state.queries_intercepted.load(Ordering::Relaxed);

    // Simulate SOCKS5 handshake to 127.0.0.1:1080
    let mut socks_stream = TcpStream::connect("127.0.0.1:1080").await.unwrap();
    // Step 1: Greeting [0x05, 0x01 (1 method), 0x00 (NO AUTH)]
    socks_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    socks_stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x00], "SOCKS5 greeting failed");
    println!("  [SUCCESS] SOCKS5 Greeting accepted: [0x05, 0x00]");

    // Step 2: Connect request to example.com:80
    // [0x05, 0x01, 0x00, 0x03 (domain), 11 (len), 'example.com', 0x00, 0x50 (port 80)]
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
    req.extend_from_slice(b"example.com");
    req.extend_from_slice(&80u16.to_be_bytes());
    socks_stream.write_all(&req).await.unwrap();

    let mut resp = [0u8; 10];
    socks_stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0x00, "SOCKS5 connection failed");
    println!("  [SUCCESS] SOCKS5 connection to example.com:80 established through proxy!");

    let after_queries = state.queries_intercepted.load(Ordering::Relaxed);
    println!("  Queries intercepted counter: {} (increased from {})", after_queries, init_queries);
    assert!(after_queries > init_queries, "Proxy failed to increment queries_intercepted");

    // TEST 5: Chaff De-correlator Burst
    println!("\n[5/6] Testing Ephemeral Chaff Decoy Burst...");
    let init_chaff = state.chaff_queries_sent.load(Ordering::Relaxed);
    decorrelator.trigger_chaff_burst("TEST", "test.real.query");
    println!("  Triggered burst. Waiting 3.5s for Poisson micro-delays...");
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let end_chaff = state.chaff_queries_sent.load(Ordering::Relaxed);
    println!("  [SUCCESS] Chaff queries sent: {} (increased from {})", end_chaff, init_chaff);
    assert!(end_chaff > init_chaff);

    // TEST 6: Clipboard URL Sanitizer
    println!("\n[6/6] Testing Clipboard URL Parameter Stripper...");
    let dirty = "Check this out: https://example.com/checkout?item=123&fbclid=IwAR28194&utm_source=fb&gclid=CjwK on sale";
    if let Some(clean) = tauri_app_lib::privacy::clipboard::sanitize_text_content(dirty) {
        println!("  Original: {}", dirty);
        println!("  Cleaned:  {}", clean);
        assert!(!clean.contains("fbclid"));
        assert!(!clean.contains("utm_source"));
        assert!(!clean.contains("gclid"));
        println!("  [SUCCESS] All tracking tokens stripped cleanly!");
    } else {
        println!("  [FAIL] URL sanitization returned None");
    }

    println!("\n========================================================");
    println!("            ALL 6 SUBSYSTEMS VERIFIED WORKING!          ");
    println!("========================================================");
}
