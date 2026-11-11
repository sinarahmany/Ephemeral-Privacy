use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaffIntensity {
    Ghost,       // Light: 2 decoys per burst
    Smokescreen, // Standard: 3-4 decoys per burst
    HeavyFog,    // Maximum: 5-8 decoys per burst
}

impl Default for ChaffIntensity {
    fn default() -> Self {
        ChaffIntensity::Smokescreen
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyEvent {
    pub id: u64,
    pub timestamp: u64,
    pub category: String, // "DNS_CHAFF", "TRACKER_BLOCKED", "SNI_FRAGMENTED", "URL_SANITIZED", "PII_MASKED"
    pub title: String,
    pub details: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyMetrics {
    pub queries_intercepted: u64,
    pub chaff_queries_sent: u64,
    pub trackers_blocked: u64,
    pub pii_sanitized: u64,
    pub sni_sliced_handshakes: u64,
    pub odoh_queries_relayed: u64,
    pub webrtc_leaks_blocked: u64,
    pub ja3_fingerprints_shuffled: u64,
    pub hardware_alerts_count: u64,
}

pub struct AppState {
    pub proxy_enabled: AtomicBool,
    pub dns_enabled: AtomicBool,
    pub chaff_enabled: AtomicBool,
    pub sni_fragmentation: AtomicBool,
    pub clipboard_cleaner: AtomicBool,
    pub pii_redactor: AtomicBool,
    pub odoh_enabled: AtomicBool,
    pub webrtc_shield: AtomicBool,
    pub ja3_shuffle: AtomicBool,
    pub hardware_sentinel_enabled: AtomicBool,
    pub minimize_to_tray: AtomicBool,
    pub chaff_intensity: RwLock<ChaffIntensity>,
    pub upstream_resolver: RwLock<String>,

    // Live Hardware Sentinel Status
    pub camera_active: AtomicBool,
    pub mic_active: AtomicBool,
    pub camera_apps: RwLock<Vec<String>>,
    pub mic_apps: RwLock<Vec<String>>,

    // Metrics (RAM-only)
    pub queries_intercepted: AtomicU64,
    pub chaff_queries_sent: AtomicU64,
    pub trackers_blocked: AtomicU64,
    pub pii_sanitized: AtomicU64,
    pub sni_sliced_handshakes: AtomicU64,
    pub odoh_queries_relayed: AtomicU64,
    pub webrtc_leaks_blocked: AtomicU64,
    pub ja3_fingerprints_shuffled: AtomicU64,
    pub hardware_alerts_count: AtomicU64,

    // Event counter & Circular Log Buffer (max 50 items, strictly RAM)
    pub event_sequence: AtomicU64,
    pub recent_events: Arc<RwLock<VecDeque<PrivacyEvent>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            proxy_enabled: AtomicBool::new(true),
            dns_enabled: AtomicBool::new(true),
            chaff_enabled: AtomicBool::new(true),
            sni_fragmentation: AtomicBool::new(true),
            clipboard_cleaner: AtomicBool::new(true),
            pii_redactor: AtomicBool::new(true),
            odoh_enabled: AtomicBool::new(true),
            webrtc_shield: AtomicBool::new(true),
            ja3_shuffle: AtomicBool::new(true),
            hardware_sentinel_enabled: AtomicBool::new(true),
            minimize_to_tray: AtomicBool::new(true),
            chaff_intensity: RwLock::new(ChaffIntensity::Smokescreen),
            upstream_resolver: RwLock::new("ODoH Relay + Rotated DoH (Quad9, Mullvad, Cloudflare)".to_string()),

            camera_active: AtomicBool::new(false),
            mic_active: AtomicBool::new(false),
            camera_apps: RwLock::new(Vec::new()),
            mic_apps: RwLock::new(Vec::new()),

            queries_intercepted: AtomicU64::new(0),
            chaff_queries_sent: AtomicU64::new(0),
            trackers_blocked: AtomicU64::new(0),
            pii_sanitized: AtomicU64::new(0),
            sni_sliced_handshakes: AtomicU64::new(0),
            odoh_queries_relayed: AtomicU64::new(0),
            webrtc_leaks_blocked: AtomicU64::new(0),
            ja3_fingerprints_shuffled: AtomicU64::new(0),
            hardware_alerts_count: AtomicU64::new(0),

            event_sequence: AtomicU64::new(0),
            recent_events: Arc::new(RwLock::new(VecDeque::with_capacity(60))),
        }
    }

    pub async fn log_event(&self, category: &str, title: &str, details: &str, target: &str) {
        let seq = self.event_sequence.fetch_add(1, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let event = PrivacyEvent {
            id: seq,
            timestamp: now,
            category: category.to_string(),
            title: title.to_string(),
            details: details.to_string(),
            target: target.to_string(),
        };

        let mut events = self.recent_events.write().await;
        if events.len() >= 50 {
            events.pop_back();
        }
        events.push_front(event);
    }

    pub fn get_metrics(&self) -> PrivacyMetrics {
        PrivacyMetrics {
            queries_intercepted: self.queries_intercepted.load(Ordering::Relaxed),
            chaff_queries_sent: self.chaff_queries_sent.load(Ordering::Relaxed),
            trackers_blocked: self.trackers_blocked.load(Ordering::Relaxed),
            pii_sanitized: self.pii_sanitized.load(Ordering::Relaxed),
            sni_sliced_handshakes: self.sni_sliced_handshakes.load(Ordering::Relaxed),
            odoh_queries_relayed: self.odoh_queries_relayed.load(Ordering::Relaxed),
            webrtc_leaks_blocked: self.webrtc_leaks_blocked.load(Ordering::Relaxed),
            ja3_fingerprints_shuffled: self.ja3_fingerprints_shuffled.load(Ordering::Relaxed),
            hardware_alerts_count: self.hardware_alerts_count.load(Ordering::Relaxed),
        }
    }
}
