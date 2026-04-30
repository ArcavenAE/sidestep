//! Header + argv redaction for the audit trail.
//!
//! v0.1 scope: redact authorization headers and any argv token that
//! looks like `--token=<...>` or `--api-key=<...>`. Field-level payload
//! redaction (charter F4 / audit-trail-format §Redaction Policy) is a
//! follow-on ticket.

use std::collections::HashSet;
use std::sync::OnceLock;

const SENSITIVE_FLAG_NAMES: &[&str] = &[
    "--token",
    "--api-key",
    "--api_token",
    "--apitoken",
    "--password",
    "--secret",
];

const SENSITIVE_HEADER_NAMES: &[&str] = &["authorization", "x-api-key", "x-auth-token", "cookie"];

pub fn is_sensitive_header(name: &str) -> bool {
    let set = sensitive_headers();
    set.contains(name.to_ascii_lowercase().as_str())
}

fn sensitive_headers() -> &'static HashSet<&'static str> {
    static H: OnceLock<HashSet<&'static str>> = OnceLock::new();
    H.get_or_init(|| SENSITIVE_HEADER_NAMES.iter().copied().collect())
}

/// Redact argv entries that look like sensitive credential flags.
/// Handles both `--token=value` and `--token value` forms.
pub fn redact_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if let Some((flag, _)) = arg.split_once('=') {
            if SENSITIVE_FLAG_NAMES.iter().any(|f| f == &flag) {
                out.push(format!("{flag}=***"));
                i += 1;
                continue;
            }
        }
        if SENSITIVE_FLAG_NAMES.iter().any(|f| f == arg) {
            out.push(arg.clone());
            if i + 1 < argv.len() {
                out.push("***".to_string());
                i += 2;
                continue;
            }
        }
        out.push(arg.clone());
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_equals_form() {
        let input: Vec<String> = ["sidestep", "--token=abc123", "runs", "list"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = redact_argv(&input);
        assert_eq!(out[1], "--token=***");
        assert_eq!(out[2], "runs");
    }

    #[test]
    fn redacts_separated_form() {
        let input: Vec<String> = ["sidestep", "--token", "abc123", "runs"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = redact_argv(&input);
        assert_eq!(out[1], "--token");
        assert_eq!(out[2], "***");
        assert_eq!(out[3], "runs");
    }

    #[test]
    fn passes_non_sensitive_through() {
        let input: Vec<String> = ["sidestep", "runs", "list", "--limit=50"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = redact_argv(&input);
        assert_eq!(out, input);
    }

    #[test]
    fn header_classifier_is_case_insensitive() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("X-API-KEY"));
        assert!(!is_sensitive_header("Content-Type"));
    }
}
