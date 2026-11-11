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

fn redact_pass<F>(
    input: &str,
    re: &Regex,
    prefix: &str,
    mut validator: F,
    token_map: &mut HashMap<String, String>,
    reverse_map: &mut HashMap<String, String>,
    redactions_count: &mut usize,
) -> String
where
    F: FnMut(&str) -> bool,
{
    let mut out = String::with_capacity(input.len());
    let mut last = 0;
    let mut idx = 1usize;

    for mat in re.find_iter(input) {
        let matched = mat.as_str();
        if !validator(matched) {
            continue;
        }
        out.push_str(&input[last..mat.start()]);
        let token = if let Some(existing) = reverse_map.get(matched) {
            existing.clone()
        } else {
            let tok = format!("<{}_{}>", prefix, idx);
            idx += 1;
            token_map.insert(tok.clone(), matched.to_string());
            reverse_map.insert(matched.to_string(), tok.clone());
            *redactions_count += 1;
            tok
        };
        out.push_str(&token);
        last = mat.end();
    }
    out.push_str(&input[last..]);
    out
}

/// Redacts sensitive PII and API keys from a prompt, generating reversible semantic tokens
pub fn redact_pii(text: &str) -> RedactionResult {
    let mut token_map = HashMap::new();
    let mut reverse_map = HashMap::new();
    let mut redactions_count = 0;

    let current = redact_pass(
        text,
        &API_KEY_REGEX,
        "API_KEY",
        |_| true,
        &mut token_map,
        &mut reverse_map,
        &mut redactions_count,
    );
    let current = redact_pass(
        &current,
        &CC_REGEX,
        "CREDIT_CARD",
        luhn_check,
        &mut token_map,
        &mut reverse_map,
        &mut redactions_count,
    );
    let current = redact_pass(
        &current,
        &EMAIL_REGEX,
        "EMAIL",
        |_| true,
        &mut token_map,
        &mut reverse_map,
        &mut redactions_count,
    );
    let current = redact_pass(
        &current,
        &PHONE_REGEX,
        "PHONE",
        |_| true,
        &mut token_map,
        &mut reverse_map,
        &mut redactions_count,
    );

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

    #[test]
    fn test_no_overlap_between_api_keys_and_phones_and_duplicates_reused() {
        let prompt = "Key sk-proj-800-555-1212-abcdef123456 email a@b.com twice: a@b.com.";
        let res = redact_pii(prompt);
        assert_eq!(res.redactions_count, 2);
        assert!(res.sanitized_text.contains("<API_KEY_1>"));
        assert!(!res.sanitized_text.contains("<PHONE_1>"));
        assert_eq!(res.sanitized_text.matches("<EMAIL_1>").count(), 2);
        assert_eq!(restore_pii(&res.sanitized_text, &res.token_map), prompt);
    }
}
