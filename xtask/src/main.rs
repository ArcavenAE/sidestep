//! xtask — developer commands for the sidestep workspace.
//!
//! Run via `cargo xtask <command>`. The companion `[alias] xtask = "run -p xtask --"`
//! lives in `.cargo/config.toml`.
//!
//! Commands (filled in by follow-on tickets):
//!   * `sync-spec`  — fetch the live OpenAPI spec, write to spec/, update sha256
//!   * `regen`      — run progenitor against vendored spec, write sidestep-api
//!   * `diff-spec`  : compare the vendored spec with upstream (or two files), summarize ops added/removed/changed

mod diff_spec;

use std::{fs, path::PathBuf, process::Command, sync::OnceLock};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
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
    /// Summarize the operations added, removed and changed between two OpenAPI files.
    ///
    /// With no flags it compares the vendored spec (old) with the live
    /// upstream spec (new), fetched and sanitized but not written anywhere.
    /// `--old` and `--new` name files instead; given alone, the other side
    /// is the vendored spec. `--against-head` compares the git HEAD copy of
    /// the vendored spec (old) with the working-tree copy (new), which is
    /// how to review what `sync-spec` just wrote.
    ///
    /// Operations are keyed on path and method. A changed operation lists
    /// its operationId, parameter, request body and response differences.
    /// Descriptions and examples are ignored.
    DiffSpec(DiffSpecArgs),
}

#[derive(Args, Debug)]
struct DiffSpecArgs {
    /// The older OpenAPI file.
    #[arg(long, value_name = "FILE", conflicts_with = "against_head")]
    old: Option<PathBuf>,
    /// The newer OpenAPI file.
    #[arg(long, value_name = "FILE", conflicts_with = "against_head")]
    new: Option<PathBuf>,
    /// Compare the git HEAD copy of the vendored spec with the working tree.
    #[arg(long)]
    against_head: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::SyncSpec => sync_spec(),
        Cmd::Regen => regen(),
        Cmd::DiffSpec(args) => diff_spec_cmd(&args),
    }
}

const GENERATED_REL_PATH: &str = "crates/sidestep-api/src/generated.rs";

fn regen() -> Result<()> {
    let workspace_root = workspace_root()?;
    let spec_path = workspace_root.join(SPEC_REL_PATH);
    let out_path = workspace_root.join(GENERATED_REL_PATH);

    eprintln!("xtask: reading spec {}", spec_path.display());
    let spec_text =
        fs::read_to_string(&spec_path).with_context(|| format!("read {}", spec_path.display()))?;
    let mut spec: openapiv3::OpenAPI =
        serde_yaml::from_str(&spec_text).context("parse spec as OpenAPI v3")?;

    let collapsed_success = collapse_multi_responses(&mut spec, ResponseClass::Success);
    let collapsed_error = collapse_multi_responses(&mut spec, ResponseClass::Error);
    if collapsed_success + collapsed_error > 0 {
        eprintln!(
            "xtask: collapsed {collapsed_success} multi-success and {collapsed_error} multi-error response(s) (progenitor requires at most one body per class)"
        );
    }
    let shadowed = drop_shadowing_non_path_params(&mut spec);
    if shadowed > 0 {
        eprintln!(
            "xtask: dropped {shadowed} non-path parameter(s) shadowing a same-name path parameter (progenitor cannot map colliding names)"
        );
    }

    eprintln!("xtask: generating client");
    let mut generator = progenitor::Generator::default();
    let tokens = generator
        .generate_tokens(&spec)
        .map_err(|e| anyhow::anyhow!("progenitor generate_tokens: {e}"))?;
    let ast = syn::parse2(tokens).context("parse generated tokens as syn AST")?;
    let body = prettyplease::unparse(&ast);

    let banner = "// Generated by `cargo xtask regen` from spec/stepsecurity-v1.yaml.\n\
                  // DO NOT EDIT BY HAND. Re-run regen to refresh.\n\
                  #![allow(unused_imports, dead_code, clippy::all)]\n\n";
    let mut content = String::with_capacity(banner.len() + body.len());
    content.push_str(banner);
    content.push_str(&body);

    fs::write(&out_path, content.as_bytes())
        .with_context(|| format!("write {}", out_path.display()))?;
    eprintln!(
        "xtask: wrote {} ({} bytes)",
        out_path.display(),
        content.len()
    );

    // prettyplease output differs from nightly rustfmt style, and the
    // fmt gate runs `cargo +nightly fmt --check` — format the generated
    // crate here so regen leaves a gate-clean tree (finding-007 gotcha).
    let fmt_status = std::process::Command::new("cargo")
        .args(["+nightly", "fmt", "-p", "sidestep-api"])
        .current_dir(&workspace_root)
        .status();
    match fmt_status {
        Ok(s) if s.success() => eprintln!("xtask: formatted sidestep-api (cargo +nightly fmt)"),
        _ => eprintln!(
            "xtask: warning: `cargo +nightly fmt -p sidestep-api` failed — run it manually before committing"
        ),
    }
    Ok(())
}

fn sync_spec() -> Result<()> {
    let workspace_root = workspace_root()?;
    let spec_path = workspace_root.join(SPEC_REL_PATH);
    let sha_path = workspace_root.join(SPEC_SHA_REL_PATH);

    let sanitized = fetch_upstream_sanitized()?;

    // Synthesize missing operationIds in the vendored copy. Keeps the spec
    // self-contained: progenitor and the SDK both read the same file with
    // every operation named. Round-trips through openapiv3 to apply the
    // mutation, then re-serializes to YAML.
    let normalized = normalize_with_synthesized_ids(&sanitized)?;

    fs::create_dir_all(spec_path.parent().expect("spec/ parent"))?;
    fs::write(&spec_path, normalized.as_bytes())
        .with_context(|| format!("write {}", spec_path.display()))?;

    let body = normalized.as_bytes();
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

/// Fetch the live spec and run the sanitize rules over it, as `sync-spec`
/// does before anything reaches disk.
fn fetch_upstream_sanitized() -> Result<String> {
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
    Ok(sanitized)
}

/// Parse a spec and give every operation an id, the same way the vendored
/// copy is prepared, so an operation with no id compares equal to itself.
fn parse_spec(label: &str, yaml: &str) -> Result<openapiv3::OpenAPI> {
    let mut spec: openapiv3::OpenAPI =
        serde_yaml::from_str(yaml).with_context(|| format!("parse {label} as OpenAPI v3"))?;
    fill_missing_operation_ids(&mut spec);
    Ok(spec)
}

fn read_spec_file(path: &std::path::Path) -> Result<openapiv3::OpenAPI> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    parse_spec(&path.display().to_string(), &text)
}

fn diff_spec_cmd(args: &DiffSpecArgs) -> Result<()> {
    let root = workspace_root()?;
    let vendored = root.join(SPEC_REL_PATH);
    let (old, new) = if args.against_head {
        let out = Command::new("git")
            .args(["show", &format!("HEAD:{SPEC_REL_PATH}")])
            .current_dir(&root)
            .output()
            .context("run git show")?;
        if !out.status.success() {
            anyhow::bail!(
                "git show HEAD:{SPEC_REL_PATH}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let head = parse_spec(
            &format!("HEAD:{SPEC_REL_PATH}"),
            &String::from_utf8_lossy(&out.stdout),
        )?;
        (head, read_spec_file(&vendored)?)
    } else {
        match (&args.old, &args.new) {
            (Some(old), Some(new)) => (read_spec_file(old)?, read_spec_file(new)?),
            (Some(old), None) => (read_spec_file(old)?, read_spec_file(&vendored)?),
            (None, Some(new)) => (read_spec_file(&vendored)?, read_spec_file(new)?),
            (None, None) => (
                read_spec_file(&vendored)?,
                parse_spec("the upstream spec", &fetch_upstream_sanitized()?)?,
            ),
        }
    };
    print!("{}", diff_spec::render(&diff_spec::diff(&old, &new)));
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

/// Round-trip the sanitized spec through openapiv3 to assign a
/// deterministic operationId to every operation that lacks one, then
/// re-serialize back to YAML. Lets the vendored on-disk file act as
/// the single source of truth: every operation is reachable by ID
/// from both progenitor (via xtask regen) and the SDK registry (which
/// reads the same file at runtime).
fn normalize_with_synthesized_ids(yaml: &str) -> Result<String> {
    let mut spec: openapiv3::OpenAPI =
        serde_yaml::from_str(yaml).context("parse spec as OpenAPI v3")?;
    let synthesized = fill_missing_operation_ids(&mut spec);
    if synthesized > 0 {
        eprintln!("xtask: synthesized {synthesized} operationId(s) into vendored spec");
    }
    serde_yaml::to_string(&spec).context("re-serialize spec to YAML")
}

/// Walk every operation in the spec and assign a deterministic
/// operationId to any that lacks one. progenitor requires every
/// operation to have an ID; some StepSecurity operations don't carry
/// one, so we derive `{method}_{path-with-params-stripped}` as a
/// stable fallback.
fn fill_missing_operation_ids(spec: &mut openapiv3::OpenAPI) -> usize {
    let mut count = 0;
    for (path, path_item) in spec.paths.paths.iter_mut() {
        let openapiv3::ReferenceOr::Item(item) = path_item else {
            continue;
        };
        for (method, op) in operations_mut(item) {
            if op.operation_id.is_none() {
                op.operation_id = Some(synthesize_operation_id(method, path));
                count += 1;
            }
        }
    }
    count
}

fn operations_mut(
    item: &mut openapiv3::PathItem,
) -> Vec<(&'static str, &mut openapiv3::Operation)> {
    let mut out: Vec<(&'static str, &mut openapiv3::Operation)> = Vec::new();
    if let Some(op) = &mut item.get {
        out.push(("get", op));
    }
    if let Some(op) = &mut item.put {
        out.push(("put", op));
    }
    if let Some(op) = &mut item.post {
        out.push(("post", op));
    }
    if let Some(op) = &mut item.delete {
        out.push(("delete", op));
    }
    if let Some(op) = &mut item.options {
        out.push(("options", op));
    }
    if let Some(op) = &mut item.head {
        out.push(("head", op));
    }
    if let Some(op) = &mut item.patch {
        out.push(("patch", op));
    }
    if let Some(op) = &mut item.trace {
        out.push(("trace", op));
    }
    out
}

#[derive(Clone, Copy)]
enum ResponseClass {
    Success,
    Error,
}

/// progenitor extracts the success and error response groups separately
/// (`is_success_or_default`, `is_error_or_default`) and asserts each
/// group's distinct Rust type count is `<= 1`. Type comes from response
/// content: an `application/json`-with-schema is a typed body, any other
/// content is `Raw`, no content is `None`. So an op with `200 {body}` +
/// `204` already trips the assertion (`Type(X)` vs `None`), even though
/// we humans read it as fine.
///
/// To accommodate the StepSecurity spec we collapse each class to a
/// single response per operation. Preference: bodied responses beat
/// unbodied; within bodied, lowest specific code beats Range/Default.
/// Dropped responses lose their schema in the generated client; CLI
/// verbs that need richer multi-status handling can read raw responses.
/// Pre-pass 4 (2026-07 spec update): some operations declare a query
/// parameter with the same name as a path parameter — e.g.
/// `GET /{customer}/developer-mdm/agent-skills/{skill_key}` carries both a
/// required `skill_key` path param and an optional `skill_key` query param
/// (an upstream escape hatch for keys containing `/` that URL-encode
/// poorly in paths). Progenitor panics on the name collision
/// ("missing path name mapping"). We keep the canonical required path
/// parameter and drop the colliding non-path duplicate; renaming instead
/// would change the on-wire query name, which is worse. Callers needing
/// the query-string escape hatch lose it in the generated client — if a
/// real key defeats path encoding, revisit with a progenitor-side rename.
fn drop_shadowing_non_path_params(spec: &mut openapiv3::OpenAPI) -> usize {
    use std::collections::HashSet;
    let mut dropped = 0;
    for (_path, path_item) in spec.paths.paths.iter_mut() {
        let openapiv3::ReferenceOr::Item(item) = path_item else {
            continue;
        };
        let base_path_names: Vec<String> = item
            .parameters
            .iter()
            .filter_map(|p| match p {
                openapiv3::ReferenceOr::Item(openapiv3::Parameter::Path {
                    parameter_data, ..
                }) => Some(parameter_data.name.clone()),
                _ => None,
            })
            .collect();
        for (_method, op) in operations_mut(item) {
            let mut path_names: HashSet<String> = base_path_names.iter().cloned().collect();
            for p in &op.parameters {
                if let openapiv3::ReferenceOr::Item(openapiv3::Parameter::Path {
                    parameter_data,
                    ..
                }) = p
                {
                    path_names.insert(parameter_data.name.clone());
                }
            }
            let before = op.parameters.len();
            op.parameters.retain(|p| match p {
                openapiv3::ReferenceOr::Item(openapiv3::Parameter::Path { .. }) => true,
                openapiv3::ReferenceOr::Item(param) => {
                    !path_names.contains(&param.parameter_data_ref().name)
                }
                openapiv3::ReferenceOr::Reference { .. } => true,
            });
            dropped += before - op.parameters.len();
        }
    }
    dropped
}

fn collapse_multi_responses(spec: &mut openapiv3::OpenAPI, class: ResponseClass) -> usize {
    use openapiv3::StatusCode;
    let mut collapsed = 0;
    for (_path, path_item) in spec.paths.paths.iter_mut() {
        let openapiv3::ReferenceOr::Item(item) = path_item else {
            continue;
        };
        for (_method, op) in operations_mut(item) {
            // (score, status_clone) — lower score = preferred to keep.
            let mut candidates: Vec<(u64, StatusCode)> = op
                .responses
                .responses
                .iter()
                .filter_map(|(status, resp)| {
                    let openapiv3::ReferenceOr::Item(r) = resp else {
                        return None;
                    };
                    response_score(status, class, !r.content.is_empty())
                        .map(|s| (s, status.clone()))
                })
                .collect();
            // openapiv3 represents the default response as a sibling field,
            // not a key in `responses`. Both classes' filters include it.
            let default_in_class = matches!(class, ResponseClass::Success | ResponseClass::Error);
            if default_in_class {
                if let Some(d) = op.responses.default.as_ref() {
                    let bodied = match d {
                        openapiv3::ReferenceOr::Item(r) => !r.content.is_empty(),
                        _ => false,
                    };
                    candidates.push((default_score(class, bodied), StatusCode::Range(0)));
                }
            }

            if candidates.len() <= 1 {
                continue;
            }

            candidates.sort_by_key(|(s, _)| *s);
            for (_score, status) in candidates.into_iter().skip(1) {
                match status {
                    StatusCode::Range(0) => {
                        // Sentinel for "default" — survives only one pass.
                        op.responses.default = None;
                    }
                    other => {
                        op.responses.responses.shift_remove(&other);
                    }
                }
                collapsed += 1;
            }
        }
    }
    collapsed
}

/// Score a status against a class. Lower = preferred. `None` means the
/// status is not in the class. Bodied entries always sort below unbodied;
/// within a tier, lower codes sort first; Range/Default fall last.
fn response_score(
    status: &openapiv3::StatusCode,
    class: ResponseClass,
    has_body: bool,
) -> Option<u64> {
    use openapiv3::StatusCode;
    let code: u64 = match (status, class) {
        (StatusCode::Code(c), ResponseClass::Success) if (200..=299).contains(c) => *c as u64,
        (StatusCode::Code(101), ResponseClass::Success) => 101,
        (StatusCode::Range(2), ResponseClass::Success) => 2_999,
        (StatusCode::Code(c), ResponseClass::Error) if (400..=599).contains(c) => *c as u64,
        (StatusCode::Range(4), ResponseClass::Error) => 4_999,
        (StatusCode::Range(5), ResponseClass::Error) => 5_999,
        _ => return None,
    };
    Some(if has_body { code } else { code + 1_000_000 })
}

fn default_score(class: ResponseClass, has_body: bool) -> u64 {
    let _ = class;
    let base: u64 = 999_999; // worse than any explicit Range
    if has_body { base } else { base + 1_000_000 }
}

fn synthesize_operation_id(method: &str, path: &str) -> String {
    let mut id = String::with_capacity(method.len() + path.len());
    id.push_str(method);
    for ch in path.chars() {
        match ch {
            '/' | '-' => id.push('_'),
            '{' | '}' => {}
            c if c.is_ascii_alphanumeric() => id.push(c.to_ascii_lowercase()),
            _ => id.push('_'),
        }
    }
    while id.contains("__") {
        id = id.replace("__", "_");
    }
    id.trim_end_matches('_').to_string()
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
