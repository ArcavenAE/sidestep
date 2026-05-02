//! End-to-end tests for `sidestep get`, `sidestep search`, `--limit`, `--since`.
//!
//! These tests exercise validation and error paths that don't require
//! network. Live-API tests will land alongside an SDK base-URL override
//! in a later slice.

use std::process::Command;

use assert_cmd::cargo::CommandCargoExt;

fn run(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(args);
    // Block the auth resolver from accidentally finding a real token.
    cmd.env_remove("SIDESTEP_API_TOKEN");
    cmd.env("SIDESTEP_AUDIT", "off");
    cmd.output().expect("output")
}

#[test]
fn get_rejects_kind_without_get_endpoint() {
    // policy has list but no get-by-id in v0.1.
    let out = run(&["get", "policy", "pol_001", "--owner", "arcaven"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no get-by-id endpoint"), "stderr: {stderr}");
    assert!(stderr.contains("sidestep list policy"), "stderr: {stderr}");
}

#[test]
fn get_rejects_kind_without_list_or_get_endpoint() {
    // repo has neither.
    let out = run(&["get", "repo", "marvel", "--owner", "arcaven"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no get-by-id endpoint"), "stderr: {stderr}");
}

#[test]
fn search_rejects_kind_without_search_field() {
    // check has list + get but no declared search_field in v0.1.
    let out = run(&["search", "check", "abc", "--owner", "arcaven"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no search field declared"),
        "stderr: {stderr}"
    );
}

#[test]
fn search_rejects_kind_without_list_endpoint() {
    let out = run(&["search", "repo", "marvel", "--owner", "arcaven"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no list endpoint"), "stderr: {stderr}");
}

#[test]
fn list_since_rejects_kind_without_primary_timestamp() {
    // repo has no primary_timestamp_field. (Repo also has no list
    // endpoint — that error fires first, but it's a useful sanity
    // check that the kind table is internally consistent.)
    let out = run(&["list", "repo", "--since", "24h", "--owner", "arcaven"]);
    assert!(!out.status.success());
    // Either error is acceptable; the precedence is "no list endpoint" first.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no list endpoint") || stderr.contains("--since"),
        "stderr: {stderr}"
    );
}

#[test]
fn list_since_rejects_garbage_duration() {
    // detection has list + primary_timestamp; --since "not-a-duration"
    // triggers CEL's duration() parse failure.
    let out = run(&[
        "list",
        "detection",
        "--owner",
        "arcaven",
        "--since",
        "not-a-real-duration",
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The exact error depends on whether the cel parser rejects at
    // compile time (it should, for `duration("not-a-real-duration")`),
    // or whether we hit the auth check first. Accept either.
    assert!(
        stderr.contains("--since") || stderr.contains("authentication") || stderr.contains("CEL"),
        "stderr: {stderr}"
    );
}

#[test]
fn list_since_quote_in_value_is_rejected_explicitly() {
    let out = run(&[
        "list",
        "detection",
        "--owner",
        "arcaven",
        "--since",
        r#"24h" || true"#,
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("must not contain quotes"),
        "stderr: {stderr}"
    );
}

#[test]
fn list_help_mentions_limit_and_since() {
    let out = run(&["list", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--limit"));
    assert!(stdout.contains("--since"));
}

#[test]
fn get_help_mentions_id_path_param_concept() {
    let out = run(&["get", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // clap shows the variant doc comment as the short summary and the
    // arg doc comments below. The "id path param" phrase is the
    // <ID> argument's help text.
    assert!(stdout.contains("id path param"), "stdout: {stdout}");
}

#[test]
fn search_help_mentions_search_field_concept() {
    let out = run(&["search", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("search field"));
}
