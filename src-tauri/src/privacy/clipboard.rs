use crate::state::AppState;
use regex::Regex;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use url::Url;

pub static TRACKING_PARAMS: &[&str] = &[
    "fbclid",
    "gclid",
    "gclsrc",
    "dclid",
    "msclkid",
    "zanpid",
    "mc_eid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_reader",
    "utm_name",
    "igshid",
    "ttclid",
    "twclid",
    "si",
    "spm",
    "_hsenc",
    "_hsmi",
    "ref_src",
    "yclid",
    "wickedid",
    "wbraid",
    "gbraid",
    "trk",
    "tracking_id",
    "vero_id",
    "vero_conv",
    "mailchimp_id",
    "oly_anon_id",
    "oly_enc_id",
    "sc_customer",
    "hsa_cam",
    "hsa_grp",
    "hsa_mt",
    "hsa_src",
    "hsa_ad",
    "hsa_acc",
    "hsa_net",
    "hsa_kw",
    "hsa_ver",
    "_branch_match_id",
    "_bta_tid",
    "_bta_c",
    "igsh",
    "srsltid",
    "gad_source",
    "gad_campaignid",
    "mc_cid",
    "_gl",
    "epik",
    "sccid",
    "s_kwcid",
    "fb_action_ids",
    "fb_action_types",
];

static URL_FINDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https?://[^\s]+").expect("Valid URL finder regex")
});

/// Strips known tracking tokens from a single URL string.
pub fn sanitize_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return None;
    }

    let mut parsed = Url::parse(trimmed).ok()?;
    let pairs: Vec<(String, String)> = parsed.query_pairs().into_owned().collect();
    if pairs.is_empty() {
        return None;
    }

    let mut stripped_any = false;
    let retained: Vec<(String, String)> = pairs
        .into_iter()
        .filter(|(key, _)| {
            let key_lower = key.to_ascii_lowercase();
            let is_tracking = TRACKING_PARAMS
                .iter()
                .any(|&param| key_lower == param || key_lower.starts_with("utm_"));
            if is_tracking {
                stripped_any = true;
                false
            } else {
                true
            }
        })
        .collect();

    if !stripped_any {
        return None;
    }

    if retained.is_empty() {
        parsed.set_query(None);
    } else {
        parsed.query_pairs_mut().clear().extend_pairs(retained);
    }
    Some(parsed.to_string())
}

/// Sanitizes any URLs found in arbitrary copied text (whether solitary or within sentences)
pub fn sanitize_text_content(text: &str) -> Option<String> {
    let mut modified = false;
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    for mat in URL_FINDER.find_iter(text) {
        result.push_str(&text[last_end..mat.start()]);
        let raw_match = mat.as_str();
        let trimmed_url = raw_match.trim_end_matches(|c: char| ".,;:!?)\"'>]".contains(c));
        let trailing_punct = &raw_match[trimmed_url.len()..];

        if let Some(cleaned_url) = sanitize_url(trimmed_url) {
            result.push_str(&cleaned_url);
            result.push_str(trailing_punct);
            modified = true;
        } else {
            result.push_str(raw_match);
        }
        last_end = mat.end();
    }

    if !modified {
        return None;
    }

    result.push_str(&text[last_end..]);
    Some(result)
}

/// Background loop monitoring system clipboard for tracking URLs
pub fn start_clipboard_monitor(state: Arc<AppState>) {
    std::thread::spawn(move || {
        let mut last_seen = String::new();
        let mut clipboard_opt = arboard::Clipboard::new().ok();

        loop {
            std::thread::sleep(Duration::from_millis(500));

            if !state.clipboard_cleaner.load(Ordering::Relaxed) {
                continue;
            }

            if clipboard_opt.is_none() {
                clipboard_opt = arboard::Clipboard::new().ok();
            }

            let clipboard = match clipboard_opt.as_mut() {
                Some(cb) => cb,
                None => continue,
            };

            let current_text = match clipboard.get_text() {
                Ok(text) => text,
                Err(_) => continue,
            };

            if current_text.is_empty() || current_text == last_seen {
                continue;
            }

            last_seen = current_text.clone();

            if let Some(cleaned) = sanitize_text_content(&current_text) {
                if let Ok(()) = clipboard.set_text(cleaned.clone()) {
                    last_seen = cleaned.clone();

                    let state_clone = state.clone();
                    tauri::async_runtime::spawn(async move {
                        state_clone.pii_sanitized.fetch_add(1, Ordering::Relaxed);
                        state_clone
                            .log_event(
                                "URL_SANITIZED",
                                "Tracking Parameters Stripped from Clipboard",
                                &format!("Sanitized URL: {}", cleaned),
                                &cleaned,
                            )
                            .await;
                    });
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_sanitization() {
        let dirty = "https://example.com/product?id=9982&fbclid=IwAR0xyz&utm_source=newsletter&utm_medium=email";
        let cleaned = sanitize_url(dirty);
        assert!(cleaned.is_some());
        let url = cleaned.unwrap();
        assert!(url.contains("id=9982"));
        assert!(!url.contains("fbclid"));
        assert!(!url.contains("utm_source"));

        let clean = "https://example.com/search?q=rust+lang";
        assert!(sanitize_url(clean).is_none());
    }

    #[test]
    fn test_text_with_embedded_url() {
        let text = "Check out this deal: https://store.com/item?id=1&gclid=xyz_tracking on sale!";
        let cleaned = sanitize_text_content(text).unwrap();
        assert_eq!(cleaned, "Check out this deal: https://store.com/item?id=1 on sale!");

        // Strip trailing tracking-only query cleanly without leaving trailing `?`, and preserve sentence period
        let all_stripped = "See https://example.com/?utm_source=fbclid.";
        assert_eq!(
            sanitize_text_content(all_stripped).unwrap(),
            "See https://example.com/."
        );
        assert_eq!(
            sanitize_url("https://example.com/path?igsh=abc123").as_deref(),
            Some("https://example.com/path")
        );
    }
}
