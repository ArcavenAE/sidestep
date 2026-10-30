//! End-to-end tests for `sidestep diff`.
//!
//! diff is a set difference over two record streams keyed on a tuple of
//! fields. The current stream is stdin; the prior one is `--against FILE`.
//! Every emitted record carries `_diff`: `added` (in current, not in
//! prior), `removed` (in prior, not in current) or `unchanged`. All
//! inputs are the synthetic spine fixtures or inline synthetic records.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::CommandCargoExt;

fn fixture(name: &str) -> String {
    let path = format!("../../examples/fixtures/{name}.jsonl");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir() -> PathBuf {
    let n = TEMPDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("sidestep-diff-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Inline synthetic record: `fields` is the body of a JSON object.
fn rec(fields: &str) -> String {
    format!(
        r#"{{"_kind":"detection","_source":{{"operation_id":"op","response_index":0,"fetched_at":"2026-04-30T10:00:00Z"}},{fields}}}"#
    )
}

/// The prior snapshot: det_001, det_002 and det_003 are still there,
/// det_099 has since gone. det_004 and det_005 are new in the fixture.
fn prior_stream() -> String {
    let current = fixture("detection");
    let mut lines: Vec<String> = current
        .lines()
        .filter(|l| l.contains(r#""id":"det_001""#) || l.contains(r#""id":"det_002""#))
        .map(str::to_string)
        .collect();
    lines.push(
        current
            .lines()
            .find(|l| l.contains(r#""id":"det_003""#))
            .unwrap()
            .to_string(),
    );
    lines.push(rec(r#""id":"det_099","severity":"low""#));
    lines.join("\n") + "\n"
}

fn run_diff(input: &str, prior: &str, args: &[&str]) -> std::process::Output {
    run_diff_with_audit(input, prior, args, None)
}

fn run_diff_with_audit(
    input: &str,
    prior: &str,
    args: &[&str],
    audit_dir: Option<&PathBuf>,
) -> std::process::Output {
    let dir = tempdir();
    let prior_path = dir.join("prior.jsonl");
    std::fs::write(&prior_path, prior).unwrap();
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.arg("diff").arg("--against").arg(&prior_path).args(args);
    cmd.env_remove("SIDESTEP_API_TOKEN");
    match audit_dir {
        Some(d) => {
            cmd.env("SIDESTEP_AUDIT_DIR", d);
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
    let out = child.wait_with_output().expect("wait");
    let _ = std::fs::remove_dir_all(&dir);
    out
}

fn parse_jsonl(s: &str) -> Vec<serde_json::Value> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid json"))
        .collect()
}

/// `id:label` pairs in output order.
fn labelled(out: &std::process::Output) -> Vec<String> {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_jsonl(&String::from_utf8(out.stdout.clone()).unwrap())
        .iter()
        .map(|r| {
            format!(
                "{}:{}",
                r["id"].as_str().unwrap(),
                r["_diff"].as_str().unwrap()
            )
        })
        .collect()
}

#[test]
fn both_is_the_default_and_emits_added_then_removed() {
    let out = run_diff(&fixture("detection"), &prior_stream(), &["--on", "id"]);
    assert_eq!(
        labelled(&out),
        ["det_004:added", "det_005:added", "det_099:removed"]
    );
}

#[test]
fn added_emits_only_what_is_new() {
    let out = run_diff(
        &fixture("detection"),
        &prior_stream(),
        &["--on", "id", "--semantics", "added"],
    );
    assert_eq!(labelled(&out), ["det_004:added", "det_005:added"]);
}

#[test]
fn removed_emits_only_what_has_gone() {
    let out = run_diff(
        &fixture("detection"),
        &prior_stream(),
        &["--on", "id", "--semantics", "removed"],
    );
    assert_eq!(labelled(&out), ["det_099:removed"]);
}

#[test]
fn include_unchanged_keeps_current_order_then_removed() {
    let out = run_diff(
        &fixture("detection"),
        &prior_stream(),
        &["--on", "id", "--include-unchanged"],
    );
    assert_eq!(
        labelled(&out),
        [
            "det_001:unchanged",
            "det_002:unchanged",
            "det_003:unchanged",
            "det_004:added",
            "det_005:added",
            "det_099:removed"
        ]
    );
}

#[test]
fn a_tuple_key_sees_a_changed_field_as_one_removed_and_one_added() {
    // Same id, different severity: with --on id,severity the prior
    // det_001 has gone and the current det_001 is new.
    let prior = rec(r#""id":"det_001","severity":"high""#);
    let current = rec(r#""id":"det_001","severity":"critical""#);
    let out = run_diff(&current, &prior, &["--on", "id,severity"]);
    assert_eq!(labelled(&out), ["det_001:added", "det_001:removed"]);
    // On id alone the same pair is unchanged.
    let out = run_diff(&current, &prior, &["--on", "id", "--include-unchanged"]);
    assert_eq!(labelled(&out), ["det_001:unchanged"]);
}

#[test]
fn key_fields_may_be_dotted_paths() {
    let prior = rec(r#""id":"a","repo":{"name":"web-api"}"#);
    let current = [
        rec(r#""id":"b","repo":{"name":"web-api"}"#),
        rec(r#""id":"c","repo":{"name":"auth-svc"}"#),
    ]
    .join("\n");
    let out = run_diff(&current, &prior, &["--on", "repo.name"]);
    assert_eq!(labelled(&out), ["c:added"]);
}

#[test]
fn records_keep_their_fields_and_gain_only_the_label() {
    let input = fixture("detection");
    let out = run_diff(&input, &prior_stream(), &["--on", "id"]);
    assert!(out.status.success());
    let before = parse_jsonl(&input);
    for rec in parse_jsonl(&String::from_utf8(out.stdout).unwrap()) {
        if rec["_diff"] == "removed" {
            continue;
        }
        let original = before.iter().find(|b| b["id"] == rec["id"]).unwrap();
        let mut stripped = rec.clone();
        stripped.as_object_mut().unwrap().remove("_diff");
        assert_eq!(&stripped, original, "only `_diff` may be added");
    }
}

#[test]
fn duplicate_keys_collapse_to_the_first_record() {
    let current = [
        rec(r#""id":"x","n":1"#),
        rec(r#""id":"x","n":2"#),
        rec(r#""id":"y","n":3"#),
    ]
    .join("\n");
    let out = run_diff(
        &current,
        &rec(r#""id":"z""#),
        &["--on", "id", "--semantics", "added"],
    );
    let records = parse_jsonl(&String::from_utf8(out.stdout.clone()).unwrap());
    assert!(out.status.success());
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["n"], 1, "first occurrence wins");
}

#[test]
fn a_record_without_a_key_field_fails_closed_and_names_it() {
    let current = [rec(r#""id":"a""#), rec(r#""severity":"low""#)].join("\n");
    let out = run_diff(&current, &rec(r#""id":"a""#), &["--on", "id"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "no partial output");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("id"), "stderr names the missing key: {err}");

    // The same holds for the prior stream.
    let out = run_diff(
        &rec(r#""id":"a""#),
        &rec(r#""severity":"low""#),
        &["--on", "id"],
    );
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn bad_arguments_are_refused() {
    let input = fixture("detection");
    let prior = prior_stream();
    // Unknown semantics.
    assert!(
        !run_diff(&input, &prior, &["--on", "id", "--semantics", "sideways"])
            .status
            .success()
    );
    // --on is required.
    assert!(!run_diff(&input, &prior, &[]).status.success());
    // An empty key path.
    assert!(
        !run_diff(&input, &prior, &["--on", "id,,severity"])
            .status
            .success()
    );
}

#[test]
fn a_missing_prior_file_is_an_error_naming_the_path() {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args([
        "diff",
        "--on",
        "id",
        "--against",
        "/nonexistent/prior.jsonl",
    ]);
    cmd.env("SIDESTEP_AUDIT", "off");
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/prior.jsonl"));
}

#[test]
fn emits_one_verb_audit_line_with_keys_and_counts() {
    let dir = tempdir();
    let out = run_diff_with_audit(
        &fixture("detection"),
        &prior_stream(),
        &["--on", "id", "--semantics", "added"],
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
    assert_eq!(lines.len(), 1, "one audit line per diff invocation");
    let line = &lines[0];
    assert_eq!(line["schema_version"], 2);
    assert_eq!(line["verb_phase"], "diff");
    assert_eq!(line["diff_keys"], serde_json::json!(["id"]));
    assert_eq!(line["diff_semantics"], "added");
    let o = &line["diff_outcome"];
    assert_eq!(o["current_count"], 5);
    assert_eq!(o["prior_count"], 4);
    assert_eq!(o["added"], 2);
    assert_eq!(o["removed"], 1);
    assert_eq!(o["unchanged"], 3);
    assert_eq!(o["emitted_count"], 2);
    assert_eq!(o["error_count"], 0);
    assert!(line.get("operation").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}
