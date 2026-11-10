use aho_corasick::AhoCorasick;
use std::sync::LazyLock;

// Comprehensive high-impact ad & tracking domain roots
pub static TRACKER_PATTERNS: &[&str] = &[
    // Major Ad Exchanges & Tracking Pixels
    "doubleclick.net",
    "google-analytics.com",
    "googletagmanager.com",
    "googlesyndication.com",
    "adservice.google.com",
    "criteo.com",
    "criteo.net",
    "adnxs.com",
    "rubiconproject.com",
    "scorecardresearch.com",
    "taboola.com",
    "outbrain.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "quantserve.com",
    "moatads.com",
    "yieldmo.com",
    "amazon-adsystem.com",
    // Social Surveillance & Ad Pixels
    "pixel.facebook.com",
    "an.facebook.com",
    "ads-twitter.com",
    "analytics.twitter.com",
    "ads.tiktok.com",
    "analytics.tiktok.com",
    "ads.pinterest.com",
    "tr.snapchat.com",
    "sc-static.net",
    "ads.linkedin.com",
    "snap.licdn.com",
    // Mobile / App Tracking & Device Fingerprinting
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "singular.net",
    "kochava.com",
    "flurry.com",
    "app-measurement.com",
    "applovin.com",
    "unityads.unity3d.com",
    "ironsrc.com",
    "vungle.com",
    "chartboost.com",
    "segment.io",
    "mixpanel.com",
    "amplitude.com",
    "hotjar.com",
    "crazyegg.com",
    "fullstory.com",
    "clarity.ms",
    // OS Telemetry
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "watson.telemetry.microsoft.com",
    "feedback.microsoft.com",
    "diagtrack.microsoft.com",
    "metrics.apple.com",
    "iadsdk.apple.com",
    "notes-analytics-events.apple.com",
    "smoot.apple.com",
    "whoopsie.canonical.com",
    "daisy.ubuntu.com",
];

static AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(TRACKER_PATTERNS)
        .expect("Failed to build AhoCorasick tracker engine")
});

pub fn is_tracker(domain: &str) -> Option<&'static str> {
    let clean = domain.trim_end_matches('.').to_ascii_lowercase();
    for mat in AC.find_iter(&clean) {
        let pattern = TRACKER_PATTERNS[mat.pattern()];
        if clean == pattern || clean.ends_with(&format!(".{}", pattern)) {
            return Some(pattern);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_detection() {
        assert!(is_tracker("adservice.google.com").is_some());
        assert!(is_tracker("subdomain.pixel.facebook.com").is_some());
        assert!(is_tracker("tracking.criteo.net").is_some());
        assert!(is_tracker("vortex.data.microsoft.com").is_some());
        assert!(is_tracker("wikipedia.org").is_none());
        assert!(is_tracker("github.com").is_none());
        assert!(is_tracker("rust-lang.org").is_none());
    }
}
