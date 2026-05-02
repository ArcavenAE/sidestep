//! End-to-end tests for `sidestep emit`.
//!
//! These tests exercise the binary via `assert_cmd` and verify that the
//! v0.1 stream contract round-trips cleanly through `--format jsonl` and
//! that `--format md` yields a markdown table with the expected columns.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

const DETECTION_LINE: &str = r#"{"_kind":"detection","_source":{"operation_id":"get_github_owner_actions_detections","response_index":0,"fetched_at":"2026-04-30T10:00:00Z"},"id":"det_001","severity":"critical","status":"open","created_at":"2026-04-29T14:23:11Z"}"#;

const RULE_LINE: &str = r#"{"_kind":"rule","_source":{"operation_id":"get_github_owner_actions_rules","response_index":0,"fetched_at":"2026-04-30T10:00:00Z"},"id":"rule_001","severity":"high","policy_id":"pol_001"}"#;

#[test]
fn emit_jsonl_passes_records_through() {
    let input = format!("{DETECTION_LINE}\n{RULE_LINE}\n");
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(["emit", "--format", "jsonl"]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        use std::io::Write;
        stdin.write_all(input.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"_kind\":\"detection\""));
    assert!(lines[0].contains("\"id\":\"det_001\""));
    assert!(lines[1].contains("\"_kind\":\"rule\""));
    assert!(lines[1].contains("\"id\":\"rule_001\""));
}

#[test]
fn emit_md_renders_a_markdown_table() {
    let input = format!("{DETECTION_LINE}\n{RULE_LINE}\n");
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(["emit", "--format", "md"]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        use std::io::Write;
        stdin.write_all(input.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("| _kind | id | severity | timestamp |"));
    assert_eq!(lines.next(), Some("|---|---|---|---|"));
    let row1 = lines.next().expect("row 1");
    assert!(row1.contains("detection"));
    assert!(row1.contains("det_001"));
    assert!(row1.contains("critical"));
    assert!(row1.contains("2026-04-29T14:23:11Z"));
    let row2 = lines.next().expect("row 2");
    assert!(row2.contains("rule"));
    assert!(row2.contains("rule_001"));
    assert!(row2.contains("high"));
}

#[test]
fn emit_passes_through_empty_input() {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(["emit", "--format", "jsonl"]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    drop(child.stdin.take()); // close stdin immediately
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn list_rejects_unknown_kind() {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(["list", "definitelyNotAKind"]);
    let out = cmd.output().expect("output");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // clap rejects with `error: invalid value` per PossibleValuesParser.
    assert!(stderr.to_lowercase().contains("invalid value"));
}

#[test]
fn list_rejects_kind_with_no_endpoint() {
    // `repo` has no list endpoint in v0.1.
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    // Ensure we don't actually try to hit the network: SIDESTEP_API_TOKEN
    // is unset by default in `cargo test`. We expect the kind check to
    // fire BEFORE the auth resolver runs.
    cmd.env_remove("SIDESTEP_API_TOKEN");
    cmd.args(["list", "repo"]);
    let out = cmd.output().expect("output");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no list endpoint"), "stderr: {stderr}");
}
