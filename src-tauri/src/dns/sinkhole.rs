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

pub const EXTRA_TRACKER_PATTERNS: &[&str] = &[
    // Google Publisher Tag, Video Ads & Conversion Trackers
    "googletagservices.com",
    "googleadservices.com",
    "adtrafficquality.google",
    "fundingchoicesmessages.google.com",
    "imasdk.googleapis.com",
    // Adobe Experience Cloud, Tag Manager & CNAME Cloaking Roots
    "adobedtm.com",
    "adobedc.net",
    "omtrdc.net",
    "demdex.net",
    "2o7.net",
    "everesttech.net",
    // News Publisher Ad-Tech, DMPs, Consent & Push Trackers (GlobalNews etc.)
    "permutive.com",
    "permutive.app",
    "parsely.com",
    "evidon.com",
    "onesignal.com",
    "stats.wp.com",
    "pixel.wp.com",
    // Programmatic Exchanges, SSPs & Header Bidding
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "indexww.com",
    "3lift.com",
    "triplelift.com",
    "sharethrough.com",
    "smartadserver.com",
    "sascdn.com",
    "adsrvr.org",
    "adnxs.com",
    "appnexus.com",
    "mediavine.com",
    "adthrive.com",
    "raptive.com",
    "sovrn.com",
    "lijit.com",
    "bidswitch.net",
    "media.net",
    "teads.tv",
    "connatix.com",
    "kargo.com",
    "gumgum.com",
    "nativo.com",
    "nativery.com",
    "yieldmo.com",
    "sonobi.com",
    "undertone.com",
    "stickyadstv.com",
    "contextweb.com",
    "pulsepoint.com",
    "springserve.com",
    "spotxchange.com",
    "spotx.tv",
    "fwmrm.net",
    "innovid.com",
    "flashtalking.com",
    "sizmek.com",
    "serving-sys.com",
    "zemanta.com",
    "revcontent.com",
    "mgid.com",
    "adform.net",
    "adition.com",
    "smartclip.net",
    "33across.com",
    "rhythmone.com",
    "emxdgt.com",
    "lkqd.net",
    "telaria.com",
    "tremorhub.com",
    "taboola.com",
    "outbrainimg.com",
    "adcolony.com",
    "vungle.com",
    "applovin.com",
    "inmobi.com",
    "unityads.unity3d.com",
    // Brand Safety, Ad Verification & Identity Stitching
    "adsafeprotected.com",
    "moatads.com",
    "doubleverify.com",
    "confiant-integrations.net",
    "iasds01.com",
    "id5-sync.com",
    "liveramp.com",
    "rlcdn.com",
    "crwdcntrl.net",
    "bluekai.com",
    "krxd.net",
    "exelator.com",
    "agkn.com",
    "tapad.com",
    "eyeota.net",
    "uidapi.com",
    "criteo.com",
    // Telemetry, Session Replay & Behavioral Analytics (host-scoped to protect dashboards)
    "chartbeat.com",
    "chartbeat.net",
    "nr-data.net",
    "js-agent.newrelic.com",
    "browser-intake-datadoghq.com",
    "optimizely.com",
    "hotjar.com",
    "fullstory.com",
    "logrocket.com",
    "mouseflow.com",
    "crazyegg.com",
    "clarity.ms",
    "heapanalytics.com",
    "api.amplitude.com",
    "api2.amplitude.com",
    "cdn.amplitude.com",
    "api.mixpanel.com",
    "cdn.mxpnl.com",
    "mxpnl.com",
    "cdn.segment.com",
    "api.segment.io",
    "segment.io",
    "mparticle.com",
    "bounceexchange.com",
    "bouncex.net",
    "wunderkind.co",
    "bat.bing.com",
    "c.bing.com",
    "clarity.bing.com",
    // Dedicated First-Party CNAME Cloaking Networks
    "eulerian.net",
    "commandersact.com",
    "dnsdelegation.io",
    "storetail.io",
    "keyade.com",
    "wizaly.com",
    "affex.org",
    "pardot.com",
    "mktoresp.com",
];

static AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(TRACKER_PATTERNS)
        .expect("Failed to build AhoCorasick tracker engine")
});

static EXTRA_AC: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(EXTRA_TRACKER_PATTERNS)
        .expect("Failed to build extended AhoCorasick tracker engine")
});

static DYNAMIC_BLOCKLIST: std::sync::OnceLock<std::sync::RwLock<std::collections::HashSet<String>>> =
    std::sync::OnceLock::new();
static DYNAMIC_RULE_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn dynamic_blocklist() -> &'static std::sync::RwLock<std::collections::HashSet<String>> {
    DYNAMIC_BLOCKLIST.get_or_init(|| std::sync::RwLock::new(std::collections::HashSet::new()))
}

pub fn total_blocklist_rules() -> usize {
    TRACKER_PATTERNS.len()
        + EXTRA_TRACKER_PATTERNS.len()
        + DYNAMIC_RULE_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

fn match_static_ac<'a>(
    ac: &AhoCorasick,
    patterns: &[&'static str],
    clean: &str,
) -> Option<&'static str> {
    for mat in ac.find_iter(clean) {
        let pattern = patterns[mat.pattern()];
        if clean == pattern
            || (clean.len() > pattern.len()
                && clean.ends_with(pattern)
                && clean.as_bytes()[clean.len() - pattern.len() - 1] == b'.')
        {
            return Some(pattern);
        }
    }
    None
}

fn match_dynamic_domain(clean: &str) -> Option<String> {
    let guard = dynamic_blocklist().read().ok()?;
    if guard.is_empty() {
        return None;
    }

    let mut suffix = clean;
    loop {
        if !suffix.contains('.') {
            break;
        }
        if guard.contains(suffix) {
            return Some(suffix.to_string());
        }
        match suffix.find('.') {
            Some(dot_idx) => suffix = &suffix[dot_idx + 1..],
            None => break,
        }
    }
    None
}

/// Checks whether a domain belongs to a known ad, tracker, or first-party CNAME cloak.
pub fn is_tracker(domain: &str) -> Option<&'static str> {
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return None;
    }

    if let Some(pat) = match_static_ac(&AC, TRACKER_PATTERNS, &clean) {
        return Some(pat);
    }
    if let Some(pat) = match_static_ac(&EXTRA_AC, EXTRA_TRACKER_PATTERNS, &clean) {
        return Some(pat);
    }
    if clean.starts_with("smetrics.") || clean.starts_with("omtrdc.") {
        return Some("first-party-cname-tracker");
    }
    if match_dynamic_domain(&clean).is_some() {
        return Some("community-blocklist");
    }
    None
}

/// Same policy check as `is_tracker`, returning the exact matched domain rule for live logs.
pub fn match_tracker(domain: &str) -> Option<String> {
    let clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return None;
    }

    if let Some(pat) = match_static_ac(&AC, TRACKER_PATTERNS, &clean) {
        return Some(pat.to_string());
    }
    if let Some(pat) = match_static_ac(&EXTRA_AC, EXTRA_TRACKER_PATTERNS, &clean) {
        return Some(pat.to_string());
    }
    if clean.starts_with("smetrics.") {
        return Some("smetrics.* (First-Party Tracker CNAME)".to_string());
    }
    if clean.starts_with("omtrdc.") {
        return Some("omtrdc.* (Adobe Tracker CNAME)".to_string());
    }
    match_dynamic_domain(&clean)
}

/// Parses plain-domain or `*.domain` wildcard filter lists cleanly into a HashSet.
fn parse_blocklist_into(raw: &str, out: &mut std::collections::HashSet<String>) {
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        let without_wild = trimmed.strip_prefix("*.").unwrap_or(trimmed);
        // Handle optional `/etc/hosts` format (`0.0.0.0 tracker.com`) safely just in case
        let candidate = if without_wild.starts_with("0.0.0.0 ") || without_wild.starts_with("127.0.0.1 ") {
            without_wild
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
        } else {
            without_wild
        };

        let clean = candidate.trim_end_matches('.').to_ascii_lowercase();
        if clean.len() >= 4
            && clean.contains('.')
            && !clean.contains(' ')
            && !clean.contains('/')
            && !clean.contains(':')
            && clean != "localhost"
            && clean != "localhost.localdomain"
        {
            out.insert(clean);
        }
    }
}

/// Fetches community ad/tracker blocklists strictly into volatile RAM (never written to disk).
pub fn spawn_blocklist_sync(state: std::sync::Arc<crate::state::AppState>) {
    state.blocklist_rules.store(
        total_blocklist_rules() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );

    tauri::async_runtime::spawn(async move {
        let client = match reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(6))
            .timeout(std::time::Duration::from_secs(20))
            .user_agent("EphemeralPrivacySuite/1.0")
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        let refresh_once = || async {
            let mut texts: Vec<String> = Vec::new();

            // 1. Compact curated root adserver list (fast ~40 KB download)
            let yoyo_url = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext";
            if let Ok(resp) = client.get(yoyo_url).send().await {
                if resp.status().is_success() {
                    if let Ok(body) = resp.text().await {
                        texts.push(body);
                    }
                }
            }

            // 2. Comprehensive community blocklist (HaGeZi Multi PRO -> OISD Small -> HaGeZi Light)
            let broad_urls = [
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
                "https://small.oisd.nl/domainswild",
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
            ];
            for url in broad_urls {
                if let Ok(resp) = client.get(url).send().await {
                    if resp.status().is_success() {
                        if let Ok(body) = resp.text().await {
                            if !body.is_empty() {
                                texts.push(body);
                                break;
                            }
                        }
                    }
                }
            }

            if texts.is_empty() {
                return None;
            }

            let parsed_set = tokio::task::spawn_blocking(move || {
                let mut set = std::collections::HashSet::with_capacity(240_000);
                for text in texts {
                    parse_blocklist_into(&text, &mut set);
                }
                set
            })
            .await
            .ok()?;

            let dynamic_count = parsed_set.len();
            if let Ok(mut guard) = dynamic_blocklist().write() {
                *guard = parsed_set;
            }
            DYNAMIC_RULE_COUNT.store(dynamic_count, std::sync::atomic::Ordering::Relaxed);
            let total = total_blocklist_rules() as u64;
            state
                .blocklist_rules
                .store(total, std::sync::atomic::Ordering::Relaxed);
            Some((dynamic_count, total))
        };

        loop {
            if let Some((dyn_count, total)) = refresh_once().await {
                state
                    .log_event(
                        "SYSTEM_BLOCKLIST",
                        "Community Ad & Tracker Filters Synced (RAM Only)",
                        &format!(
                            "Loaded {} community + {} built-in domain rules ({} total) in volatile memory — zero disk storage.",
                            dyn_count,
                            TRACKER_PATTERNS.len() + EXTRA_TRACKER_PATTERNS.len(),
                            total
                        ),
                        "ram://blocklist",
                    )
                    .await;
            }
            // Refresh every 6 hours while running
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
        }
    });
}

#[cfg(test)]
mod extended_sinkhole_tests {
    use super::*;

    #[test]
    fn test_globalnews_trackers_blocked_without_false_positives() {
        let blocked = [
            "www.googletagservices.com",
            "c.amazon-adsystem.com",
            "widgets.outbrain.com",
            "assets.adobedtm.com",
            "smetrics.globalnews.ca",
            "globalnews.ca.data.adobedc.net",
            "api.permutive.com",
            "f7e98148-cb09-4cf1-9b9f-b5aee3465d6e.edge.permutive.app",
            "cdn.parsely.com",
            "experiments.parsely.com",
            "c.evidon.com",
            "cdn.onesignal.com",
            "sb.scorecardresearch.com",
            "stats.wp.com",
            "securepubads.g.doubleclick.net",
        ];
        for host in blocked {
            assert!(
                is_tracker(host).is_some(),
                "Expected tracker/ad host '{}' to be blocked",
                host
            );
            assert!(match_tracker(host).is_some());
        }

        let allowed = [
            "globalnews.ca",
            "static.globalnews.ca",
            "widgets.media.weather.com",
            "i0.wp.com",
            "i1.wp.com",
            "api.w.org",
            "track.canadapost.ca",
            "newrelic.com",
        ];
        for host in allowed {
            assert!(
                is_tracker(host).is_none(),
                "Expected legitimate host '{}' NOT to be blocked (matched {:?})",
                host,
                match_tracker(host)
            );
        }
    }

    #[test]
    fn test_parse_blocklist_formats_and_suffix_walk() {
        let sample = "# comment\r\n*.tracker-wild.example\r\nad-host.example\n0.0.0.0 metrics-hosts.example\nlocalhost\n";
        let mut set = std::collections::HashSet::new();
        parse_blocklist_into(sample, &mut set);
        assert!(set.contains("tracker-wild.example"));
        assert!(set.contains("ad-host.example"));
        assert!(set.contains("metrics-hosts.example"));
        assert!(!set.contains("localhost"));

        if let Ok(mut guard) = dynamic_blocklist().write() {
            for item in set {
                guard.insert(item);
            }
        }
        assert!(is_tracker("sub.deep.tracker-wild.example").is_some());
        assert_eq!(
            match_tracker("sub.deep.tracker-wild.example").as_deref(),
            Some("tracker-wild.example")
        );
        assert!(is_tracker("nottracker-wild.example").is_none());

        if let Ok(mut guard) = dynamic_blocklist().write() {
            guard.remove("tracker-wild.example");
            guard.remove("ad-host.example");
            guard.remove("metrics-hosts.example");
        }
    }
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
