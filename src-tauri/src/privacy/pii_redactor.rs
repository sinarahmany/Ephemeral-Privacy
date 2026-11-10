use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").expect("Valid email regex")
});

static PHONE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b")
        .expect("Valid phone regex")
});

static API_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sk-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{50,})\b")
        .expect("Valid api key regex")
});

static CC_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\d{4}[- ]?){3}\d{4}\b").expect("Valid credit card regex")
});

pub fn luhn_check(num_str: &str) -> bool {
    let digits: Vec<u32> = num_str
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        if double {
            let d = digit * 2;
            sum += if d > 9 { d - 9 } else { d };
        } else {
            sum += digit;
        }
        double = !double;
    }

    sum % 10 == 0
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RedactionResult {
    pub sanitized_text: String,
    pub redactions_count: usize,
    pub token_map: HashMap<String, String>,
}

/// Redacts sensitive PII and API keys from a prompt, generating reversible semantic tokens
pub fn redact_pii(text: &str) -> RedactionResult {
    let mut current = text.to_string();
    let mut token_map = HashMap::new();
    let mut redactions_count = 0;

    // 1. API Keys & Secrets
    let mut api_idx = 1;
    for mat in API_KEY_REGEX.find_iter(text) {
        let key_str = mat.as_str().to_string();
        let token = format!("<API_KEY_{}>", api_idx);
        token_map.insert(token.clone(), key_str.clone());
        current = current.replace(&key_str, &token);
        api_idx += 1;
        redactions_count += 1;
    }

    // 2. Credit Cards (Luhn verified)
    let mut cc_idx = 1;
    for mat in CC_REGEX.find_iter(text) {
        let cc_str = mat.as_str().to_string();
        if luhn_check(&cc_str) {
            let token = format!("<CREDIT_CARD_{}>", cc_idx);
            token_map.insert(token.clone(), cc_str.clone());
            current = current.replace(&cc_str, &token);
            cc_idx += 1;
            redactions_count += 1;
        }
    }

    // 3. Email Addresses
    let mut email_idx = 1;
    for mat in EMAIL_REGEX.find_iter(text) {
        let email_str = mat.as_str().to_string();
        let token = format!("<EMAIL_{}>", email_idx);
        token_map.insert(token.clone(), email_str.clone());
        current = current.replace(&email_str, &token);
        email_idx += 1;
        redactions_count += 1;
    }

    // 4. Phone Numbers
    let mut phone_idx = 1;
    for mat in PHONE_REGEX.find_iter(text) {
        let phone_str = mat.as_str().to_string();
        let token = format!("<PHONE_{}>", phone_idx);
        token_map.insert(token.clone(), phone_str.clone());
        current = current.replace(&phone_str, &token);
        phone_idx += 1;
        redactions_count += 1;
    }

    RedactionResult {
        sanitized_text: current,
        redactions_count,
        token_map,
    }
}

/// De-anonymizes LLM reply text by replacing tokens back with their original sensitive values
pub fn restore_pii(text: &str, token_map: &HashMap<String, String>) -> String {
    let mut result = text.to_string();
    for (token, original) in token_map {
        result = result.replace(token, original);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_and_key_redaction() {
        let prompt = "Please review my auth header Authorization: Bearer sk-1234567890abcdef1234567890 and email admin@company.com with logs.";
        let res = redact_pii(prompt);
        assert!(res.sanitized_text.contains("<API_KEY_1>"));
        assert!(res.sanitized_text.contains("<EMAIL_1>"));
        assert!(!res.sanitized_text.contains("sk-1234567890"));
        assert!(!res.sanitized_text.contains("admin@company.com"));

        // Reverse check
        let restored = restore_pii(&res.sanitized_text, &res.token_map);
        assert_eq!(restored, prompt);
    }

    #[test]
    fn test_credit_card_luhn_detection() {
        // Valid Visa test card (passes Luhn)
        let valid_cc = "4532 0151 1283 0366";
        assert!(luhn_check(valid_cc));

        // Invalid CC (fails Luhn)
        let invalid_cc = "4532 0151 1283 0367";
        assert!(!luhn_check(invalid_cc));

        let text = format!("Customer billing card is {}", valid_cc);
        let res = redact_pii(&text);
        assert!(res.sanitized_text.contains("<CREDIT_CARD_1>"));
        assert!(!res.sanitized_text.contains("4532"));
    }
}
