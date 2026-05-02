//! End-to-end tests for the v2 audit schema.
//!
//! Verifies that:
//!   * `schema_version` is bumped to 2 on every emission
//!   * `verb_phase` and (where applicable) `synthesis_keys` ride along
//!     on API-shape emissions for list/get/search/api
//!   * stream-transform verbs (filter/enrich) emit a verb-shape line
//!     with the recipe-specific fields per finding-001
//!
//! These tests redirect audit output to a per-test tempdir via
//! `SIDESTEP_AUDIT_DIR` so they don't pollute the user's real trail.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use assert_cmd::cargo::CommandCargoExt;

fn fixture_path(name: &str) -> String {
    format!("../../examples/fixtures/{name}.jsonl")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name)).expect("read fixture")
}

use std::sync::atomic::{AtomicU64, Ordering};

static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir() -> PathBuf {
    let n = TEMPDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("sidestep-audit-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_audit_lines(dir: &PathBuf) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let read = std::fs::read_dir(dir).expect("read audit dir");
    for entry in read.flatten() {
        if entry.path().extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let body = std::fs::read_to_string(entry.path()).unwrap();
        for line in body.lines() {
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line).expect("audit line is JSON"));
        }
    }
    out
}

#[test]
fn filter_emits_v2_verb_event_with_predicate_fields() {
    let dir = tempdir();

    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep");
    cmd.args(["filter", "--where", r#"severity == "critical""#]);
    cmd.env("SIDESTEP_AUDIT_DIR", &dir);
    cmd.env_remove("SIDESTEP_API_TOKEN");
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture("detection").as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    let lines = read_audit_lines(&dir);
    assert_eq!(lines.len(), 1, "one audit line per filter invocation");
    let line = &lines[0];

    assert_eq!(line["schema_version"], 2);
    assert_eq!(line["verb_phase"], "filter");
    assert_eq!(line["predicate_text"], r#"severity == "critical""#);
    assert!(
        line["predicate_ast_shape"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"),
        "ast_shape: {line:?}"
    );
    assert_eq!(line["predicate_outcome"]["kept_count"], 1);
    assert_eq!(line["predicate_outcome"]["dropped_count"], 4);
    assert_eq!(line["predicate_outcome"]["error_count"], 0);
    // No operation/response on a verb-shape line.
    assert!(line.get("operation").is_none());
    assert!(line.get("response").is_none());

    cleanup(&dir);
}

#[test]
fn filter_ast_shape_is_value_independent() {
    // Two predicates with the same shape but different literals must
    // hash to the same predicate_ast_shape.
    let dir_a = tempdir();
    let dir_b = tempdir();

    for (dir, predicate) in [
        (&dir_a, r#"severity == "critical""#),
        (&dir_b, r#"severity == "high""#),
    ] {
        let mut cmd = Command::cargo_bin("sidestep").expect("sidestep");
        cmd.args(["filter", "--where", predicate]);
        cmd.env("SIDESTEP_AUDIT_DIR", dir);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(fixture("detection").as_bytes())
            .unwrap();
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
    }

    let shape_a = read_audit_lines(&dir_a)[0]["predicate_ast_shape"]
        .as_str()
        .unwrap()
        .to_string();
    let shape_b = read_audit_lines(&dir_b)[0]["predicate_ast_shape"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(shape_a, shape_b, "shape must be value-independent");

    cleanup(&dir_a);
    cleanup(&dir_b);
}

#[test]
fn filter_ast_shape_changes_when_structure_changes() {
    let dir_a = tempdir();
    let dir_b = tempdir();

    for (dir, predicate) in [
        (&dir_a, r#"severity == "critical""#),
        (&dir_b, r#"severity in ["critical", "high"]"#),
    ] {
        let mut cmd = Command::cargo_bin("sidestep").expect("sidestep");
        cmd.args(["filter", "--where", predicate]);
        cmd.env("SIDESTEP_AUDIT_DIR", dir);
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(fixture("detection").as_bytes())
            .unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap();
    }

    let shape_a = read_audit_lines(&dir_a)[0]["predicate_ast_shape"]
        .as_str()
        .unwrap()
        .to_string();
    let shape_b = read_audit_lines(&dir_b)[0]["predicate_ast_shape"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(shape_a, shape_b, "different operators must change shape");

    cleanup(&dir_a);
    cleanup(&dir_b);
}

#[test]
fn enrich_emits_v2_verb_event_with_recipe_id() {
    let dir = tempdir();

    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep");
    cmd.args([
        "enrich",
        "--with",
        "severity-roll-up",
        "--policies",
        &fixture_path("policy"),
    ]);
    cmd.env("SIDESTEP_AUDIT_DIR", &dir);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture("rule").as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    let lines = read_audit_lines(&dir);
    assert_eq!(lines.len(), 1);
    let line = &lines[0];

    assert_eq!(line["schema_version"], 2);
    assert_eq!(line["verb_phase"], "enrich");
    assert_eq!(line["recipe_id"], "severity-roll-up");
    assert_eq!(line["transform_outcome"]["transformed_count"], 5);
    assert_eq!(line["transform_outcome"]["error_count"], 0);
    assert_eq!(line["auxiliary"]["policies_loaded"], 3);

    cleanup(&dir);
}

#[test]
fn audit_can_be_disabled_with_off_env() {
    let dir = tempdir();
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep");
    cmd.args(["filter", "--where", r#"severity == "critical""#]);
    cmd.env("SIDESTEP_AUDIT_DIR", &dir);
    cmd.env("SIDESTEP_AUDIT", "off");
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture("detection").as_bytes())
        .unwrap();
    drop(child.stdin.take());
    child.wait_with_output().unwrap();

    let lines = read_audit_lines(&dir);
    assert_eq!(lines.len(), 0, "SIDESTEP_AUDIT=off must silence emission");

    cleanup(&dir);
}

#[test]
fn pipeline_filter_then_enrich_emits_two_verb_lines() {
    let dir = tempdir();

    // First stage: filter
    let mut filter = Command::cargo_bin("sidestep").expect("sidestep");
    filter.args(["filter", "--where", r#"_kind == "rule""#]);
    filter.env("SIDESTEP_AUDIT_DIR", &dir);
    filter.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut filter_child = filter.spawn().unwrap();
    filter_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture("rule").as_bytes())
        .unwrap();
    drop(filter_child.stdin.take());
    let filter_out = filter_child.wait_with_output().unwrap();
    assert!(filter_out.status.success());

    // Second stage: enrich on the filtered output
    let mut enrich = Command::cargo_bin("sidestep").expect("sidestep");
    enrich.args([
        "enrich",
        "--with",
        "policy-context",
        "--policies",
        &fixture_path("policy"),
    ]);
    enrich.env("SIDESTEP_AUDIT_DIR", &dir);
    enrich.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut enrich_child = enrich.spawn().unwrap();
    enrich_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&filter_out.stdout)
        .unwrap();
    drop(enrich_child.stdin.take());
    enrich_child.wait_with_output().unwrap();

    let lines = read_audit_lines(&dir);
    assert_eq!(lines.len(), 2, "filter + enrich → two audit lines");
    let phases: Vec<&str> = lines
        .iter()
        .map(|l| l["verb_phase"].as_str().unwrap())
        .collect();
    assert!(phases.contains(&"filter"));
    assert!(phases.contains(&"enrich"));

    cleanup(&dir);
}

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}
