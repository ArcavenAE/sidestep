//! xtask — developer commands for the sidestep workspace.
//!
//! Run via `cargo xtask <command>`. The companion `[alias] xtask = "run -p xtask --"`
//! lives in `.cargo/config.toml`.
//!
//! Commands (filled in by follow-on tickets):
//!   * `sync-spec`  — fetch the live OpenAPI spec, write to spec/, update sha256
//!   * `regen`      — run progenitor against vendored spec, write sidestep-api
//!   * `diff-spec`  — compare local vendored spec vs upstream, summarize ops added/removed/changed

use std::{fs, path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use sha2::{Digest, Sha256};

const SPEC_URL: &str = "https://app.stepsecurity.io/assets/shared/step-security-api-v1.yaml";
const SPEC_REL_PATH: &str = "spec/stepsecurity-v1.yaml";
const SPEC_SHA_REL_PATH: &str = "spec/stepsecurity-v1.yaml.sha256";

/// Sanitization rules: every regex match is replaced by its placeholder
/// before the spec lands on disk. Source code stores patterns, not
/// literal secrets — both because GitHub push protection scans this
/// file too, and because a literal-needle approach can't catch new
/// secret-shaped examples that share a pattern.
///
/// Add a rule here when `sync-spec` surfaces a new pattern. Do not
/// add an `--allow-secrets` flag to bypass.
struct SanitizeRule {
    pattern: &'static str,
    replacement: &'static str,
    description: &'static str,
}

const SANITIZE_RULES: &[SanitizeRule] = &[SanitizeRule {
    pattern: r"https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+",
    replacement: "https://hooks.slack.com/services/SLACK-TEAM-EXAMPLE/SLACK-BOT-EXAMPLE/SLACK-WEBHOOK-EXAMPLE",
    description: "Slack incoming-webhook URL",
}];

fn compiled_rules() -> &'static [(Regex, &'static str, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        SANITIZE_RULES
            .iter()
            .map(|r| {
                (
                    Regex::new(r.pattern).expect("sanitize rule regex"),
                    r.replacement,
                    r.description,
                )
            })
            .collect()
    })
}

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "Developer tasks for sidestep")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Fetch the upstream OpenAPI spec and update the vendored copy.
    SyncSpec,
    /// Regenerate sidestep-api from the vendored spec. Not yet implemented.
    Regen,
    /// Diff the vendored spec against upstream. Not yet implemented.
    DiffSpec,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::SyncSpec => sync_spec(),
        Cmd::Regen => {
            anyhow::bail!(
                "xtask regen: not yet implemented (follow-on ticket: progenitor wire-up)"
            );
        }
        Cmd::DiffSpec => {
            anyhow::bail!("xtask diff-spec: not yet implemented (follow-on ticket)");
        }
    }
}

fn sync_spec() -> Result<()> {
    let workspace_root = workspace_root()?;
    let spec_path = workspace_root.join(SPEC_REL_PATH);
    let sha_path = workspace_root.join(SPEC_SHA_REL_PATH);

    eprintln!("xtask: fetching spec from {SPEC_URL}");
    let body = reqwest::blocking::get(SPEC_URL)
        .context("fetch spec")?
        .error_for_status()
        .context("spec endpoint returned non-2xx")?
        .text()
        .context("read spec body")?;

    let (sanitized, applied) = sanitize(&body);
    if applied > 0 {
        eprintln!("xtask: sanitized {applied} secret-shaped example(s) before writing");
    }

    fs::create_dir_all(spec_path.parent().expect("spec/ parent"))?;
    fs::write(&spec_path, sanitized.as_bytes())
        .with_context(|| format!("write {}", spec_path.display()))?;

    let body = sanitized.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest = hex::encode(hasher.finalize());
    fs::write(&sha_path, format!("{digest}  stepsecurity-v1.yaml\n"))
        .with_context(|| format!("write {}", sha_path.display()))?;

    eprintln!(
        "xtask: wrote {} ({} bytes)",
        spec_path.display(),
        body.len()
    );
    eprintln!("xtask: sha256 {digest}");
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    // CARGO_MANIFEST_DIR points at xtask/; one level up is the workspace root.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR unset")?;
    Ok(PathBuf::from(manifest_dir)
        .parent()
        .context("xtask has no parent dir")?
        .to_path_buf())
}

/// Apply each compiled rule. Returns the rewritten body and the count
/// of substitutions made.
fn sanitize(input: &str) -> (String, usize) {
    let mut out = input.to_string();
    let mut applied = 0;
    for (regex, replacement, _description) in compiled_rules() {
        let n = regex.find_iter(&out).count();
        if n > 0 {
            out = regex.replace_all(&out, *replacement).into_owned();
            applied += n;
        }
    }
    (out, applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic Slack-webhook-shaped URL from fragments. The full
    /// URL is never present as a source literal — that's deliberate, so
    /// GitHub's secret-scanner doesn't flag the test as a real webhook.
    fn synthetic_slack_url() -> String {
        let prefix = "https://hooks.slack.com/";
        let api = "services/";
        let team = "TXXXXXXXXXX";
        let bot = "BXXXXXXXXXX";
        // 24 lowercase placeholder chars — same shape as a real token, no value.
        let token = "x".repeat(24);
        format!("{prefix}{api}{team}/{bot}/{token}")
    }

    #[test]
    fn sanitize_rewrites_slack_webhook_shape() {
        let url = synthetic_slack_url();
        let input = format!("url: {url}\n");
        let (out, n) = sanitize(&input);
        assert_eq!(n, 1);
        assert!(!out.contains(&url));
        assert!(out.contains("SLACK-WEBHOOK-EXAMPLE"));
    }

    #[test]
    fn sanitize_handles_multiple_occurrences() {
        let input = concat!(
            "a: https://hooks.slack.com/services/TAAA/BAAA/aaaaaaaaaaaaaaaa\n",
            "b: https://hooks.slack.com/services/TBBB/BBBB/bbbbbbbbbbbbbbbb\n",
        );
        let (_, n) = sanitize(input);
        assert_eq!(n, 2);
    }

    #[test]
    fn sanitize_is_a_noop_when_clean() {
        let input = "no secrets here\n";
        let (out, n) = sanitize(input);
        assert_eq!(n, 0);
        assert_eq!(out, input);
    }
}
