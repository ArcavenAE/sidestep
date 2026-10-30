//! End-to-end tests for `sidestep rank`.
//!
//! rank orders a record stream by typed fields, deterministically:
//! the same input and the same keys give the same output. All inputs
//! are the synthetic spine fixtures or inline synthetic records.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::CommandCargoExt;

fn fixture(name: &str) -> String {
    let path = format!("../../examples/fixtures/{name}.jsonl");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

fn run_rank(input: &str, args: &[&str]) -> std::process::Output {
    run_rank_with_audit(input, args, None)
}

fn run_rank_with_audit(
    input: &str,
    args: &[&str],
    audit_dir: Option<&PathBuf>,
) -> std::process::Output {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.arg("rank").args(args);
    cmd.env_remove("SIDESTEP_API_TOKEN");
    match audit_dir {
        Some(dir) => {
            cmd.env("SIDESTEP_AUDIT_DIR", dir);
        }
        None => {
            cmd.env("SIDESTEP_AUDIT", "off");
        }
    }
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
    drop(child.stdin.take());
    child.wait_with_output().expect("wait")
}

fn parse_jsonl(s: &str) -> Vec<serde_json::Value> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid json"))
        .collect()
}

fn ids(out: &std::process::Output) -> Vec<String> {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_jsonl(&String::from_utf8(out.stdout.clone()).unwrap())
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_string())
        .collect()
}

/// Inline synthetic records: `_kind` and `_source` are the stream
/// contract, `fields` is a JSON object body.
fn rec(fields: &str) -> String {
    format!(
        r#"{{"_kind":"detection","_source":{{"operation_id":"op","response_index":0,"fetched_at":"2026-04-30T10:00:00Z"}},{fields}}}"#
    )
}

#[test]
fn default_direction_is_highest_first() {
    // created_at is an RFC 3339 string: newest first by default.
    let out = run_rank(&fixture("detection"), &["--by", "created_at"]);
    assert_eq!(
        ids(&out),
        ["det_002", "det_001", "det_004", "det_003", "det_005"]
    );
}

#[test]
fn severity_sorts_by_severity_order_not_alphabet() {
    // Alphabetical descending would put "medium" first.
    let out = run_rank(&fixture("detection"), &["--by", "severity"]);
    assert_eq!(
        ids(&out),
        ["det_001", "det_002", "det_003", "det_004", "det_005"]
    );
    let out = run_rank(&fixture("detection"), &["--by", "severity:asc"]);
    assert_eq!(
        ids(&out),
        ["det_005", "det_004", "det_003", "det_002", "det_001"]
    );
}

#[test]
fn later_keys_break_ties_of_earlier_keys() {
    let out = run_rank(
        &fixture("detection"),
        &["--by", "status:asc", "--by", "severity:desc"],
    );
    // open (critical, high, low), then resolved, then suppressed.
    assert_eq!(
        ids(&out),
        ["det_001", "det_002", "det_004", "det_005", "det_003"]
    );
}

#[test]
fn dotted_paths_reach_nested_fields_and_ties_keep_input_order() {
    let out = run_rank(&fixture("detection"), &["--by", "repo.name:asc"]);
    // det_001 and det_003 share repo.name = infra; input order holds.
    assert_eq!(
        ids(&out),
        ["det_005", "det_004", "det_001", "det_003", "det_002"]
    );
}

#[test]
fn top_keeps_the_first_n_after_ranking() {
    let out = run_rank(&fixture("detection"), &["--by", "severity", "--top", "2"]);
    assert_eq!(ids(&out), ["det_001", "det_002"]);
}

#[test]
fn numbers_compare_as_numbers() {
    let input = [
        rec(r#""id":"a","score":9"#),
        rec(r#""id":"b","score":10"#),
        rec(r#""id":"c","score":2"#),
    ]
    .join("\n");
    let out = run_rank(&input, &["--by", "score"]);
    assert_eq!(ids(&out), ["b", "a", "c"]);
}

#[test]
fn records_missing_the_field_go_last_in_both_directions() {
    let input = [
        rec(r#""id":"a""#),
        rec(r#""id":"b","severity":"low""#),
        rec(r#""id":"c","severity":null"#),
        rec(r#""id":"d","severity":"high""#),
    ]
    .join("\n");
    let out = run_rank(&input, &["--by", "severity:desc"]);
    assert_eq!(ids(&out), ["d", "b", "a", "c"]);
    let out = run_rank(&input, &["--by", "severity:asc"]);
    assert_eq!(ids(&out), ["b", "d", "a", "c"]);
}

#[test]
fn unknown_severity_values_rank_below_every_known_one() {
    let input = [
        rec(r#""id":"a","severity":"banana""#),
        rec(r#""id":"b","severity":"info""#),
        rec(r#""id":"c","severity":"critical""#),
    ]
    .join("\n");
    let out = run_rank(&input, &["--by", "severity"]);
    assert_eq!(ids(&out), ["c", "b", "a"]);
}

#[test]
fn records_pass_through_unchanged() {
    let input = fixture("detection");
    let out = run_rank(&input, &["--by", "severity"]);
    assert!(out.status.success());
    let before = parse_jsonl(&input);
    let after = parse_jsonl(&String::from_utf8(out.stdout).unwrap());
    for rec in &after {
        let same = before.iter().find(|b| b["id"] == rec["id"]).unwrap();
        assert_eq!(rec, same, "rank must not add, drop or rewrite fields");
    }
}

#[test]
fn refuses_a_bad_direction_a_zero_top_and_a_missing_key() {
    let out = run_rank(&fixture("detection"), &["--by", "severity:sideways"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("sideways"),
        "stderr names the bad direction: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());

    let out = run_rank(&fixture("detection"), &["--by", "severity", "--top", "0"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());

    let out = run_rank(&fixture("detection"), &[]);
    assert!(!out.status.success(), "--by is required");
}

#[test]
fn a_malformed_line_fails_closed_with_no_output() {
    let input = format!("{}\nnot json\n", rec(r#""id":"a","severity":"low""#));
    let out = run_rank(&input, &["--by", "severity"]);
    assert!(!out.status.success());
    assert!(
        out.stdout.is_empty(),
        "a partial ranking must not be emitted: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir() -> PathBuf {
    let n = TEMPDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("sidestep-rank-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn emits_one_verb_audit_line_with_the_ranking_the_agent_expressed() {
    let dir = tempdir();
    let out = run_rank_with_audit(
        &fixture("detection"),
        &["--by", "severity", "--by", "created_at:asc", "--top", "3"],
        Some(&dir),
    );
    assert!(out.status.success());

    let mut lines = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("jsonl") {
            for l in std::fs::read_to_string(entry.path()).unwrap().lines() {
                lines.push(serde_json::from_str::<serde_json::Value>(l).unwrap());
            }
        }
    }
    assert_eq!(lines.len(), 1, "one audit line per rank invocation");
    let line = &lines[0];
    assert_eq!(line["schema_version"], 2);
    assert_eq!(line["verb_phase"], "rank");
    assert_eq!(
        line["rank_keys"],
        serde_json::json!([
            {"path": "severity", "direction": "desc"},
            {"path": "created_at", "direction": "asc"}
        ])
    );
    assert_eq!(line["rank_outcome"]["input_count"], 5);
    assert_eq!(line["rank_outcome"]["emitted_count"], 3);
    assert_eq!(line["rank_outcome"]["top"], 3);
    assert!(line.get("operation").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
