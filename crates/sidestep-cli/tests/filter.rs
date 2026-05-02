//! End-to-end tests for `sidestep filter`.

use std::io::Write;
use std::process::{Command, Stdio};

use assert_cmd::cargo::CommandCargoExt;

fn fixture(name: &str) -> String {
    let path = format!("../../examples/fixtures/{name}.jsonl");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

fn run_filter(input: &str, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.arg("filter").args(args);
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

#[test]
fn keeps_records_matching_string_equality() {
    let out = run_filter(
        &fixture("detection"),
        &["--where", r#"severity == "critical""#],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"id\":\"det_001\""));
}

#[test]
fn keeps_records_matching_in_operator() {
    let out = run_filter(
        &fixture("detection"),
        &["--where", r#"severity in ["critical", "high"]"#],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
}

#[test]
fn supports_track_c_triage_predicate_verbatim() {
    // From examples/recipes/triage.sh — the canonical "critical-first" policy.
    let out = run_filter(
        &fixture("detection"),
        &[
            "--where",
            r#"(severity == "critical" || severity == "high") && status == "open""#,
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let count = stdout.lines().count();
    assert_eq!(
        count, 2,
        "expected 2 critical-or-high open detections, got {count}"
    );
}

#[test]
fn has_macro_works_via_record_view() {
    let out = run_filter(
        &fixture("detection"),
        &["--where", "has(record.suppressed_by)"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    // Only det_003 has suppressed_by in the fixture.
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"id\":\"det_003\""));
}

#[test]
fn explain_prints_predicate_and_schema_without_consuming_stdin() {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(["filter", "--where", r#"severity == "high""#, "--explain"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("predicate: severity == \"high\""));
    assert!(stdout.contains("now:"));
    assert!(stdout.contains("ast:"));
    assert!(stdout.contains("v0.1 kind schemas"));
    assert!(stdout.contains("detection"));
    assert!(stdout.contains("policy"));
}

#[test]
fn rejects_predicate_returning_non_bool() {
    let out = run_filter(&fixture("detection"), &["--where", r#"severity"#]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("must return bool"), "stderr: {stderr}");
}

#[test]
fn timestamp_comparison_against_now_works() {
    // All fixture timestamps are in the past, so `created_at < now` keeps everything.
    let out = run_filter(&fixture("detection"), &["--where", "created_at < now"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), fixture("detection").lines().count());
}

#[test]
fn filter_then_emit_md_pipeline() {
    // Compose `filter` and `emit` in one process tree.
    let mut filter = Command::cargo_bin("sidestep").expect("sidestep");
    filter.args([
        "filter",
        "--where",
        r#"_kind == "detection" && severity == "critical""#,
    ]);
    filter.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut filter_child = filter.spawn().expect("spawn filter");
    filter_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(fixture("detection").as_bytes())
        .unwrap();
    drop(filter_child.stdin.take());
    let filter_out = filter_child.wait_with_output().expect("wait filter");
    assert!(filter_out.status.success());

    let mut emit = Command::cargo_bin("sidestep").expect("sidestep");
    emit.args(["emit", "--format", "md"]);
    emit.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut emit_child = emit.spawn().expect("spawn emit");
    emit_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&filter_out.stdout)
        .unwrap();
    drop(emit_child.stdin.take());
    let emit_out = emit_child.wait_with_output().expect("wait emit");
    assert!(emit_out.status.success());

    let table = String::from_utf8(emit_out.stdout).unwrap();
    assert!(table.contains("| _kind | id | severity | timestamp |"));
    assert!(table.contains("det_001"));
    assert!(table.contains("critical"));
    // Higher-severity-only filter dropped the high/medium/low/info rows.
    assert!(!table.contains("det_002"));
}
