//! End-to-end tests for `cargo xtask diff-spec`.
//!
//! diff-spec compares two OpenAPI files and reports the operations added,
//! removed and changed, keyed on method and path. The fixtures are small
//! synthetic specs; nothing here touches the network or the vendored spec.

use std::process::{Command, Output};

const OLD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/diff_old.yaml");
const NEW: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/diff_new.yaml");

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("diff-spec")
        .args(args)
        .output()
        .expect("run xtask")
}

fn stdout_of(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn section<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("no {heading:?} in:\n{text}"));
    let rest = &text[start..];
    let end = rest[heading.len()..]
        .find("\n\n")
        .map_or(rest.len(), |i| i + heading.len());
    &rest[..end]
}

#[test]
fn lists_an_added_operation_with_method_path_and_id() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    let added = section(&text, "added (1)");
    assert!(added.contains("+ POST /e  createE"), "{added}");
}

#[test]
fn lists_a_removed_operation() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    let removed = section(&text, "removed (1)");
    assert!(removed.contains("- GET /c  getC"), "{removed}");
}

#[test]
fn reports_parameter_and_response_changes_on_a_kept_operation() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    let changed = section(&text, "changed (3)");
    assert!(changed.contains("~ GET /a  listA"), "{changed}");
    assert!(
        changed.contains("parameter added: query since"),
        "{changed}"
    );
    assert!(
        changed.contains("parameter now required: query limit"),
        "{changed}"
    );
    assert!(changed.contains("response added: 404"), "{changed}");
}

#[test]
fn reports_a_request_body_schema_change() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    let changed = section(&text, "changed (3)");
    assert!(changed.contains("~ POST /b  createB"), "{changed}");
    assert!(
        changed.contains("request body changed: application/json"),
        "{changed}"
    );
}

#[test]
fn reports_an_operation_id_change() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    let changed = section(&text, "changed (3)");
    assert!(changed.contains("~ GET /d/{id}  getDetail"), "{changed}");
    assert!(
        changed.contains("operationId: getD -> getDetail"),
        "{changed}"
    );
}

#[test]
fn an_unchanged_operation_is_not_listed() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    assert!(!text.contains("listB"), "{text}");
}

#[test]
fn an_operation_without_an_id_on_both_sides_is_not_a_change() {
    // /f carries no operationId in either file; both get the same
    // synthesized id, so it is not reported.
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    assert!(!text.contains("/f"), "{text}");
}

#[test]
fn counts_component_schemas_added_removed_and_changed() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    assert!(
        text.contains("schemas: 1 added (Fresh), 1 removed (Gone), 1 changed (Thing)"),
        "{text}"
    );
}

#[test]
fn ends_with_a_summary_line() {
    let text = stdout_of(&["--old", OLD, "--new", NEW]);
    let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap();
    assert_eq!(last, "summary: 1 added, 1 removed, 3 changed, 2 unchanged");
}

#[test]
fn identical_files_report_no_differences() {
    let text = stdout_of(&["--old", OLD, "--new", OLD]);
    assert!(text.contains("no differences"), "{text}");
    assert!(
        text.contains("summary: 0 added, 0 removed, 0 changed, 6 unchanged"),
        "{text}"
    );
}

#[test]
fn output_is_deterministic() {
    let a = stdout_of(&["--old", OLD, "--new", NEW]);
    let b = stdout_of(&["--old", OLD, "--new", NEW]);
    assert_eq!(a, b);
}

#[test]
fn swapping_the_files_swaps_added_and_removed() {
    let text = stdout_of(&["--old", NEW, "--new", OLD]);
    assert!(text.contains("- POST /e  createE"), "{text}");
    assert!(text.contains("+ GET /c  getC"), "{text}");
}

#[test]
fn a_missing_file_is_an_error_naming_the_path() {
    let out = run(&["--old", "/nonexistent/old.yaml", "--new", NEW]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/old.yaml"));
}

#[test]
fn a_file_that_is_not_an_openapi_spec_is_an_error() {
    let dir = std::env::temp_dir().join(format!("xtask-diff-spec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.yaml");
    std::fs::write(&bad, "not: an openapi document\n").unwrap();
    let out = run(&["--old", bad.to_str().unwrap(), "--new", NEW]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad.yaml"));
}

#[test]
fn against_head_cannot_be_combined_with_explicit_files() {
    let out = run(&["--against-head", "--old", OLD]);
    assert!(!out.status.success());
}

#[test]
fn help_says_what_the_defaults_compare() {
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["diff-spec", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("vendored"), "{help}");
    assert!(help.contains("upstream"), "{help}");
    assert!(help.contains("--against-head"), "{help}");
}
