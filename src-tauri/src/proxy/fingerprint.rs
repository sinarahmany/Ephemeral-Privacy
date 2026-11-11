use rand::seq::{IndexedRandom, SliceRandom};
use reqwest::Client;
use rustls::crypto::aws_lc_rs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

static GENERIC_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
];

#[derive(Clone)]
pub struct FingerprintProfile {
    pub name: &'static str,
    pub client: Client,
    pub user_agent: &'static str,
}

/// Manages a rotating pool of HTTP clients with shuffled TLS cipher suite orders (JA3/JA4 diversity)
/// and normalized generic User-Agent headers.
#[derive(Clone)]
pub struct FingerprintPool {
    profiles: Arc<Vec<FingerprintProfile>>,
    rr_index: Arc<AtomicUsize>,
}

impl FingerprintPool {
    pub fn new() -> Self {
        let mut profiles = Vec::new();
        let profile_names = [
            "Profile-A (Safari-like Suite Order)",
            "Profile-B (Chrome-like Suite Order)",
            "Profile-C (Firefox-like Suite Order)",
            "Profile-D (ChaCha20-First Suite Order)",
        ];

        for (i, &name) in profile_names.iter().enumerate() {
            let ua = GENERIC_USER_AGENTS[i % GENERIC_USER_AGENTS.len()];
            let client = build_shuffled_tls_client(i, ua).unwrap_or_else(|e| {
                eprintln!("Warning: fallback TLS profile {}: {}", name, e);
                Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(4))
                    .user_agent(ua)
                    .build()
                    .unwrap_or_else(|_| Client::new())
            });
            profiles.push(FingerprintProfile {
                name,
                client,
                user_agent: ua,
            });
        }

        Self {
            profiles: Arc::new(profiles),
            rr_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Selects a rotated TLS fingerprint profile
    pub fn next_profile(&self) -> &FingerprintProfile {
        let idx = self.rr_index.fetch_add(1, Ordering::Relaxed) % self.profiles.len();
        &self.profiles[idx]
    }

    /// Selects a randomized TLS fingerprint profile
    pub fn random_profile(&self) -> &FingerprintProfile {
        let mut rng = rand::rng();
        self.profiles.choose(&mut rng).unwrap_or(&self.profiles[0])
    }
}

/// Builds a `reqwest::Client` whose `rustls::ClientConfig` uses a distinct cipher suite order
/// to vary the TLS ClientHello JA3/JA4 fingerprint across outbound DoH / ODoH / chaff traffic.
fn build_shuffled_tls_client(variant: usize, user_agent: &str) -> Result<Client, String> {
    let mut provider = aws_lc_rs::default_provider();
    let mut suites = provider.cipher_suites.clone();

    match variant % 4 {
        0 => {
            // Keep default (typically AES-GCM-128 / 256 / ChaCha20)
        }
        1 => {
            // Rotate forward by 1 within TLS 1.3 and TLS 1.2 suites
            suites.reverse();
        }
        2 => {
            // Shuffle deterministically per build/startup
            let mut rng = rand::rng();
            suites.shuffle(&mut rng);
        }
        _ => {
            // Prioritize ChaCha20 / ECDHE variations
            let shift = suites.len().min(2);
            suites.rotate_left(shift);
        }
    }

    provider.cipher_suites = suites;
    let provider = Arc::new(provider);

    let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|e| format!("Platform verifier error: {}", e))?;

    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("Protocol versions error: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    tls_config.alpn_protocols = if variant % 2 == 0 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec(), b"h2".to_vec()]
    };

    Client::builder()
        .no_proxy()
        .use_preconfigured_tls(tls_config)
        .timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(45))
        .user_agent(user_agent)
        .build()
        .map_err(|e| format!("Reqwest client build error: {}", e))
}

/// Normalizes identifying HTTP headers in plaintext HTTP requests forwarded through the proxy.
pub fn normalize_http_request_headers(raw_http: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw_http).ok()?;
    let header_end = text.find("\r\n\r\n")?;
    let (headers_part, body_part) = text.split_at(header_end);

    let mut rng = rand::rng();
    let generic_ua = *GENERIC_USER_AGENTS.choose(&mut rng)?;

    let mut normalized_lines = Vec::new();
    let mut saw_ua = false;

    for (idx, line) in headers_part.split("\r\n").enumerate() {
        if idx == 0 {
            normalized_lines.push(line.to_string());
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("user-agent:") {
            normalized_lines.push(format!("User-Agent: {}", generic_ua));
            saw_ua = true;
        } else if lower.starts_with("x-client-data:")
            || lower.starts_with("x-forwarded-for:")
            || lower.starts_with("via:")
        {
            // Strip client fingerprinting / proxy chain hints
            continue;
        } else {
            normalized_lines.push(line.to_string());
        }
    }

    if !saw_ua {
        normalized_lines.push(format!("User-Agent: {}", generic_ua));
    }

    let mut out = normalized_lines.join("\r\n").into_bytes();
    out.extend_from_slice(body_part.as_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_header_normalization() {
        let raw = b"GET /test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: CustomLeakyApp/9.1\r\nX-Client-Data: secret123\r\nAccept: */*\r\n\r\nbody";
        let normalized = normalize_http_request_headers(raw).unwrap();
        let text = String::from_utf8(normalized).unwrap();
        assert!(!text.contains("CustomLeakyApp/9.1"));
        assert!(!text.contains("X-Client-Data"));
        assert!(text.contains("User-Agent: Mozilla/5.0"));
        assert!(text.ends_with("\r\n\r\nbody"));
    }
}
