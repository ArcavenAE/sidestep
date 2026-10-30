//! End-to-end tests for `sidestep replay`.
//!
//! replay reads the local audit trail and emits the spans one trace id
//! produced. It returns what was called and the shape of each response,
//! not the records: the trail stores no payloads. All trail files here
//! are hand-written synthetic spans in a per-test directory.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::CommandCargoExt;

const T1: &str = "01900000-0000-7000-8000-000000000001";
const T2: &str = "01900000-0000-7000-8000-000000000002";

static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir() -> PathBuf {
    let n = TEMPDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "sidestep-replay-{}-{n}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One synthetic v2 API-shape span.
fn span(trace: &str, span_id: &str, ts: &str, items: u64) -> String {
    serde_json::json!({
        "schema_version": 2,
        "trace_id": trace,
        "span_id": span_id,
        "parent_span_id": null,
        "ts_start": ts,
        "duration_ms": 12,
        "verb_phase": "list",
        "invocation": {
            "argv": ["sidestep", "list", "detection"],
            "binary_version": "0.1.0",
            "build_id": "dev+gabcdef0",
            "tty": false,
            "auth_source": "env"
        },
        "operation": {
            "id": "get_github_owner_actions_detections",
            "method": "GET",
            "url_template": "/github/{owner}/actions/detections",
            "path_params": {"owner": "acme-corp"},
            "query_params": {}
        },
        "response": {
            "status": 200,
            "size_bytes": 1234,
            "items_returned": items,
            "shape_hash": "sha256:00ff"
        },
        "result": "ok",
        "redacted_fields": []
    })
    .to_string()
}

/// A trail directory with two day files. T1 has span s1 and s3 in the
/// first file (s3 is later than s2) and s2 in the second; T2 has one.
fn trail() -> PathBuf {
    let dir = tempdir();
    std::fs::write(
        dir.join("2026-10-01.jsonl"),
        [
            span(T1, "s1", "2026-10-01T10:00:00.000Z", 5),
            span(T2, "x1", "2026-10-01T10:00:01.000Z", 9),
            "this line is not json".to_string(),
            String::new(),
            span(T1, "s3", "2026-10-01T10:00:09.000Z", 7),
        ]
        .join("\n")
            + "\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("2026-10-02.jsonl"),
        span(T1, "s2", "2026-10-01T10:00:05.000Z", 6) + "\n",
    )
    .unwrap();
    dir
}

fn run_replay(trail: &Path, args: &[&str], audit: bool) -> std::process::Output {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.arg("replay").args(args);
    cmd.env_remove("SIDESTEP_API_TOKEN");
    cmd.env("SIDESTEP_AUDIT_DIR", trail);
    if !audit {
        // The trail is still read from SIDESTEP_AUDIT_DIR; only the
        // writing of replay's own span is off.
        cmd.env("SIDESTEP_AUDIT", "off");
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn()
        .expect("spawn")
        .wait_with_output()
        .expect("wait")
}

fn parse_jsonl(s: &str) -> Vec<serde_json::Value> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid json"))
        .collect()
}

fn span_ids(out: &std::process::Output) -> Vec<String> {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_jsonl(&String::from_utf8(out.stdout.clone()).unwrap())
        .iter()
        .map(|r| r["span_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn emits_the_spans_of_one_trace_in_time_order_across_files() {
    let dir = trail();
    let out = run_replay(&dir, &[T1], false);
    // s2 sits in the later file but happened between s1 and s3.
    assert_eq!(span_ids(&out), ["s1", "s2", "s3"]);
}

#[test]
fn a_trace_id_selects_only_its_own_spans() {
    let dir = trail();
    let out = run_replay(&dir, &[T2], false);
    assert_eq!(span_ids(&out), ["x1"]);
}

#[test]
fn each_span_is_a_stream_record_with_a_trace_pointer() {
    let dir = trail();
    let out = run_replay(&dir, &[T1], false);
    let records = parse_jsonl(&String::from_utf8(out.stdout).unwrap());
    let first = &records[0];
    assert_eq!(first["_kind"], "audit_span");
    assert_eq!(first["_source"]["operation_id"], "audit_trail");
    assert_eq!(first["_source"]["trace_ref"], format!("{T1}:s1"));
    // The span's own fields ride along unchanged.
    assert_eq!(
        first["operation"]["id"],
        "get_github_owner_actions_detections"
    );
    assert_eq!(first["response"]["items_returned"], 5);
    assert_eq!(first["response"]["shape_hash"], "sha256:00ff");
}

#[test]
fn replay_returns_shapes_and_no_records() {
    let dir = trail();
    let out = run_replay(&dir, &[T1], false);
    let text = String::from_utf8(out.stdout).unwrap();
    for rec in parse_jsonl(&text) {
        let response = rec["response"].as_object().unwrap();
        assert!(
            !response.contains_key("data") && !response.contains_key("items"),
            "the trail holds no payload, so replay emits none: {response:?}"
        );
    }
}

#[test]
fn the_output_composes_with_the_other_stream_verbs() {
    let dir = trail();
    let replay = run_replay(&dir, &[T1], false);
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(["rank", "--by", "response.items_returned"]);
    cmd.env("SIDESTEP_AUDIT", "off");
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&replay.stdout)
        .unwrap();
    drop(child.stdin.take());
    let ranked = child.wait_with_output().unwrap();
    assert_eq!(span_ids(&ranked), ["s3", "s2", "s1"]);
}

#[test]
fn an_unknown_trace_is_an_error_not_an_empty_success() {
    let dir = trail();
    let out = run_replay(&dir, &["01900000-0000-7000-8000-0000000000ff"], false);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("01900000-0000-7000-8000-0000000000ff"),
        "{err}"
    );
}

#[test]
fn a_missing_trail_directory_is_an_error_naming_it() {
    let dir = trail().join("no-such-subdir");
    let out = run_replay(&dir, &[T1], false);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no-such-subdir"));
}

#[test]
fn odd_trace_ids_are_refused_before_any_read() {
    let dir = trail();
    for bad in ["../x", "a/b", "", "has space", "semi;colon"] {
        let out = run_replay(&dir, &[bad], false);
        assert!(!out.status.success(), "{bad:?} must be refused");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn help_says_what_replay_does_not_return() {
    let out = Command::cargo_bin("sidestep")
        .unwrap()
        .args(["replay", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("not the records"),
        "help must state the limit: {help}"
    );
}

#[test]
fn emits_one_verb_audit_line_with_the_trace_and_the_counts() {
    let dir = trail();
    let out = run_replay(&dir, &[T1], true);
    assert!(out.status.success());
    // replay appends its own span to today's file; find it by phase.
    let mut own = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        for l in std::fs::read_to_string(entry.path()).unwrap().lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
                if v["verb_phase"] == "replay" {
                    own.push(v);
                }
            }
        }
    }
    assert_eq!(own.len(), 1, "one audit line per replay invocation");
    let line = &own[0];
    assert_eq!(line["schema_version"], 2);
    assert_eq!(line["replay_trace_id"], T1);
    let o = &line["replay_outcome"];
    assert_eq!(o["spans_found"], 3);
    assert_eq!(o["files_read"], 2);
    assert_eq!(o["lines_unparsed"], 1);
    assert_eq!(o["emitted_count"], 3);
    assert_eq!(o["error_count"], 0);
    assert!(line.get("operation").is_none());
}
