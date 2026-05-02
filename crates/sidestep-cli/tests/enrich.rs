//! End-to-end tests for `sidestep enrich`.
//!
//! Covers all three v0.1 recipes (policy-context, severity-roll-up,
//! repo-owner) against the spine fixtures so the cross-kind-enrich
//! semantic that Track B's shell asserts validate is also enforced
//! via the Rust binary.

use std::io::Write;
use std::process::{Command, Stdio};

use assert_cmd::cargo::CommandCargoExt;

fn fixture(name: &str) -> String {
    let path = format!("../../examples/fixtures/{name}.jsonl");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

fn fixture_path(name: &str) -> String {
    format!("../../examples/fixtures/{name}.jsonl")
}

fn run_enrich(input: &str, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.arg("enrich").args(args);
    cmd.env_remove("SIDESTEP_API_TOKEN");
    cmd.env("SIDESTEP_AUDIT", "off");
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write");
    child.wait_with_output().expect("wait")
}

fn parse_jsonl(s: &str) -> Vec<serde_json::Value> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid json"))
        .collect()
}

#[test]
fn policy_context_attaches_parent_to_each_rule() {
    let out = run_enrich(
        &fixture("rule"),
        &[
            "--with",
            "policy-context",
            "--policies",
            &fixture_path("policy"),
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records = parse_jsonl(&String::from_utf8(out.stdout).unwrap());

    // rule_001..rule_004 have policies that exist; rule_005 is orphan.
    let by_id: std::collections::HashMap<String, &serde_json::Value> = records
        .iter()
        .map(|r| (r["id"].as_str().unwrap().to_string(), r))
        .collect();

    assert_eq!(
        by_id["rule_001"]["policy"]["id"].as_str(),
        Some("pol_001"),
        "rule_001 → pol_001"
    );
    assert_eq!(
        by_id["rule_002"]["policy"]["id"].as_str(),
        Some("pol_002"),
        "rule_002 → pol_002"
    );
    assert_eq!(
        by_id["rule_003"]["policy"]["id"].as_str(),
        Some("pol_001"),
        "rule_003 → pol_001"
    );
    assert_eq!(
        by_id["rule_004"]["policy"]["id"].as_str(),
        Some("pol_001"),
        "rule_004 → pol_001"
    );
    assert!(
        by_id["rule_005"]["policy"].is_null(),
        "rule_005 (parent pol_999 absent) → null"
    );
}

#[test]
fn policy_context_passes_through_non_rules() {
    let out = run_enrich(
        &fixture("detection"),
        &[
            "--with",
            "policy-context",
            "--policies",
            &fixture_path("policy"),
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records = parse_jsonl(&String::from_utf8(out.stdout).unwrap());
    assert!(!records.is_empty());
    for r in &records {
        assert_eq!(r["_kind"].as_str(), Some("detection"));
        assert!(
            r.get("policy").is_none(),
            "detection records should not get a policy attached: {}",
            r["id"]
        );
    }
}

#[test]
fn policy_context_requires_policies_flag() {
    let out = run_enrich(&fixture("rule"), &["--with", "policy-context"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("requires --policies"), "stderr: {stderr}");
}

#[test]
fn severity_rollup_takes_max_with_parent_policy() {
    let out = run_enrich(
        &fixture("rule"),
        &[
            "--with",
            "severity-roll-up",
            "--policies",
            &fixture_path("policy"),
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records = parse_jsonl(&String::from_utf8(out.stdout).unwrap());
    let by_id: std::collections::HashMap<String, &serde_json::Value> = records
        .iter()
        .map(|r| (r["id"].as_str().unwrap().to_string(), r))
        .collect();

    // rule_004 is medium under pol_001 (high) — rollup must be high.
    assert_eq!(by_id["rule_004"]["severity"].as_str(), Some("medium"));
    assert_eq!(by_id["rule_004"]["severity_rollup"].as_str(), Some("high"));

    // rule_001 is high under pol_001 (high) — rollup high.
    assert_eq!(by_id["rule_001"]["severity_rollup"].as_str(), Some("high"));

    // rule_005 is orphan — keeps its own severity (low).
    assert_eq!(by_id["rule_005"]["severity_rollup"].as_str(), Some("low"));
}

#[test]
fn severity_rollup_works_without_policies_for_self_severity() {
    let out = run_enrich(&fixture("detection"), &["--with", "severity-roll-up"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records = parse_jsonl(&String::from_utf8(out.stdout).unwrap());
    assert!(!records.is_empty());
    for r in &records {
        let sev = r["severity"].as_str();
        let rollup = r["severity_rollup"].as_str();
        assert_eq!(sev, rollup, "detection rollup must equal own severity: {r}");
    }
}

#[test]
fn repo_owner_hoists_top_level_field_for_detections() {
    let out = run_enrich(&fixture("detection"), &["--with", "repo-owner"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records = parse_jsonl(&String::from_utf8(out.stdout).unwrap());
    for r in &records {
        let nested = r["repo"]["owner"].as_str();
        let hoisted = r["_repo_owner"].as_str();
        assert_eq!(nested, hoisted, "hoist must mirror nested owner");
        assert!(nested.is_some(), "detection fixtures all have repo.owner");
    }
}

#[test]
fn repo_owner_passes_through_records_without_repo() {
    // rule fixtures don't have a repo field.
    let out = run_enrich(&fixture("rule"), &["--with", "repo-owner"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let records = parse_jsonl(&String::from_utf8(out.stdout).unwrap());
    for r in &records {
        assert!(r.get("_repo_owner").is_none(), "rule should pass through");
    }
}

#[test]
fn rejects_unknown_recipe() {
    let out = run_enrich(&fixture("rule"), &["--with", "totally-fake"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown recipe"), "stderr: {stderr}");
}

#[test]
fn rejects_policies_file_with_wrong_kind() {
    // detection.jsonl is not policy records.
    let out = run_enrich(
        &fixture("rule"),
        &[
            "--with",
            "policy-context",
            "--policies",
            &fixture_path("detection"),
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kinds other than `policy`"),
        "stderr: {stderr}"
    );
}

#[test]
fn enrich_then_filter_then_emit_pipeline() {
    // Triage-shaped pipeline: enrich rules with severity rollup, filter
    // to high+critical, emit markdown. Validates that enriched fields
    // are visible to the filter primitive.
    let mut enrich = Command::cargo_bin("sidestep").expect("sidestep");
    enrich.args([
        "enrich",
        "--with",
        "severity-roll-up",
        "--policies",
        &fixture_path("policy"),
    ]);
    enrich.env("SIDESTEP_AUDIT", "off");
    enrich.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut enrich_child = enrich.spawn().expect("spawn enrich");
    enrich_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture("rule").as_bytes())
        .unwrap();
    drop(enrich_child.stdin.take());
    let enrich_out = enrich_child.wait_with_output().expect("wait enrich");
    assert!(
        enrich_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&enrich_out.stderr)
    );

    let mut filter = Command::cargo_bin("sidestep").expect("sidestep");
    filter.args([
        "filter",
        "--where",
        r#"severity_rollup in ["critical", "high"]"#,
    ]);
    filter.env("SIDESTEP_AUDIT", "off");
    filter.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut filter_child = filter.spawn().expect("spawn filter");
    filter_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&enrich_out.stdout)
        .unwrap();
    drop(filter_child.stdin.take());
    let filter_out = filter_child.wait_with_output().expect("wait filter");
    assert!(
        filter_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&filter_out.stderr)
    );

    let kept = parse_jsonl(&String::from_utf8(filter_out.stdout).unwrap());
    let ids: Vec<&str> = kept.iter().map(|r| r["id"].as_str().unwrap()).collect();
    // rule_001 (high), rule_003 (high), rule_004 (medium→rolls up to high under pol_001).
    // rule_002 stays medium (parent pol_002 medium). rule_005 stays low (orphan).
    assert!(ids.contains(&"rule_001"), "ids: {ids:?}");
    assert!(ids.contains(&"rule_003"), "ids: {ids:?}");
    assert!(ids.contains(&"rule_004"), "ids: {ids:?}");
    assert!(!ids.contains(&"rule_002"), "ids: {ids:?}");
    assert!(!ids.contains(&"rule_005"), "ids: {ids:?}");
}
