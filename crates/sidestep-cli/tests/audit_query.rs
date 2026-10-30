//! End-to-end tests for `sidestep audit query`.
//!
//! The reader mines the local audit trail: a corpus summary, counts grouped
//! by a field, and operations that occur close together in time. It reads
//! the trail only and makes no API call. All trails here are hand-written
//! synthetic spans in a per-test directory.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::{Value, json};

static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir() -> PathBuf {
    let n = TEMPDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "sidestep-auditq-{}-{n}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One synthetic span. `op` is None for a verb span that has no operation.
fn span(ts: &str, phase: &str, op: Option<&str>, status: Option<u16>, result: &str) -> String {
    let mut v = json!({
        "schema_version": 2,
        "trace_id": "01900000-0000-7000-8000-000000000001",
        "span_id": format!("s-{ts}"),
        "parent_span_id": null,
        "ts_start": ts,
        "duration_ms": 10,
        "verb_phase": phase,
        "invocation": {
            "argv": ["sidestep", phase],
            "binary_version": "0.1.0",
            "build_id": "dev+gabcdef0",
            "tty": false,
            "auth_source": "env"
        },
        "result": result,
        "redacted_fields": []
    });
    if let Some(op) = op {
        v["operation"] = json!({"id": op, "method": "GET", "url_template": "/x"});
    }
    if let Some(s) = status {
        v["response"] = json!({"status": s, "size_bytes": 1});
    }
    v.to_string()
}

/// Two day files. Day 1: opA, opB 30 s later, opA again at +4 min. Day 2:
/// opC, a filter span, opC again, a span with an unusable time, a line that
/// is not JSON and a blank line.
fn trail() -> PathBuf {
    let dir = tempdir();
    let day1 = [
        span(
            "2026-10-01T10:00:00.000Z",
            "api",
            Some("opA"),
            Some(200),
            "ok",
        ),
        span(
            "2026-10-01T10:00:30.000Z",
            "api",
            Some("opB"),
            Some(200),
            "ok",
        ),
        span(
            "2026-10-01T10:04:00.000Z",
            "api",
            Some("opA"),
            Some(400),
            "http_error",
        ),
    ];
    let day2 = [
        span(
            "2026-10-02T09:00:00.000Z",
            "api",
            Some("opC"),
            Some(200),
            "ok",
        ),
        span("2026-10-02T09:00:10.000Z", "filter", None, None, "ok"),
        span(
            "2026-10-02T09:00:20.000Z",
            "api",
            Some("opC"),
            Some(200),
            "ok",
        ),
        span("not-a-time", "api", Some("opZ"), Some(200), "ok"),
        "this line is not json".to_string(),
        String::new(),
    ];
    std::fs::write(dir.join("2026-10-01.jsonl"), day1.join("\n") + "\n").unwrap();
    std::fs::write(dir.join("2026-10-02.jsonl"), day2.join("\n") + "\n").unwrap();
    dir
}

fn run_in(dir: &Path, args: &[&str], audit: bool) -> std::process::Output {
    let mut cmd = Command::cargo_bin("sidestep").expect("sidestep binary");
    cmd.args(["audit", "query"]).args(args);
    cmd.env_remove("SIDESTEP_API_TOKEN");
    cmd.env("SIDESTEP_AUDIT_DIR", dir);
    if !audit {
        cmd.env("SIDESTEP_AUDIT", "off");
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().unwrap().wait_with_output().unwrap()
}

fn records(out: &std::process::Output) -> Vec<Value> {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid json"))
        .collect()
}

/// `key=count` pairs of the group records, in output order.
fn groups(out: &std::process::Output) -> Vec<String> {
    records(out)
        .iter()
        .filter(|r| r["_kind"] == "audit_group")
        .map(|r| format!("{}={}", r["key"].as_str().unwrap(), r["count"]))
        .collect()
}

/// `a+b=count` for the pair records, in output order.
fn pairs(out: &std::process::Output) -> Vec<String> {
    records(out)
        .iter()
        .filter(|r| r["_kind"] == "audit_pair")
        .map(|r| {
            format!(
                "{}+{}={}",
                r["a"].as_str().unwrap(),
                r["b"].as_str().unwrap(),
                r["count"]
            )
        })
        .collect()
}

#[test]
fn a_bare_query_summarizes_the_corpus() {
    let dir = trail();
    let recs = records(&run_in(&dir, &[], false));
    assert_eq!(recs.len(), 1);
    let c = &recs[0];
    assert_eq!(c["_kind"], "audit_corpus");
    assert_eq!(c["_source"]["operation_id"], "audit_trail");
    assert_eq!(c["records"], 6);
    assert_eq!(c["active_days"], 2);
    assert_eq!(c["first_ts"], "2026-10-01T10:00:00.000Z");
    assert_eq!(c["last_ts"], "2026-10-02T09:00:20.000Z");
    assert_eq!(c["files_read"], 2);
}

#[test]
fn damaged_input_is_counted_not_hidden() {
    let dir = trail();
    let c = &records(&run_in(&dir, &[], false))[0];
    assert_eq!(c["lines_unparsed"], 1);
    assert_eq!(c["spans_without_time"], 1);
}

#[test]
fn group_by_a_dotted_path_counts_highest_first_then_by_key() {
    let dir = trail();
    let out = run_in(&dir, &["--group-by", "operation.id"], false);
    assert_eq!(
        groups(&out),
        ["opA=2", "opC=2", "<none>=1", "opB=1"],
        "ties break on the key; a missing field is <none>"
    );
}

#[test]
fn group_records_name_the_field() {
    let dir = trail();
    let recs = records(&run_in(&dir, &["--group-by", "result"], false));
    assert_eq!(recs[0]["field"], "result");
    assert_eq!(recs[0]["key"], "ok");
    assert_eq!(recs[0]["count"], 5);
}

#[test]
fn group_by_a_number_uses_its_text() {
    let dir = trail();
    let out = run_in(&dir, &["--group-by", "response.status"], false);
    assert_eq!(groups(&out), ["200=4", "400=1", "<none>=1"]);
}

#[test]
fn group_by_day_uses_the_utc_date_of_ts_start() {
    let dir = trail();
    let out = run_in(&dir, &["--group-by", "_day"], false);
    assert_eq!(groups(&out), ["2026-10-01=3", "2026-10-02=3"]);
}

#[test]
fn top_keeps_the_first_n_groups() {
    let dir = trail();
    let out = run_in(&dir, &["--group-by", "operation.id", "--top", "2"], false);
    assert_eq!(groups(&out), ["opA=2", "opC=2"]);
}

#[test]
fn since_a_date_keeps_spans_from_that_utc_midnight() {
    let dir = trail();
    let out = run_in(
        &dir,
        &["--since", "2026-10-02", "--group-by", "operation.id"],
        false,
    );
    assert_eq!(groups(&out), ["opC=2", "<none>=1"]);
}

#[test]
fn since_a_timestamp_keeps_spans_at_or_after_it() {
    let dir = trail();
    let out = run_in(
        &dir,
        &[
            "--since",
            "2026-10-01T10:04:00Z",
            "--group-by",
            "operation.id",
        ],
        false,
    );
    assert_eq!(groups(&out), ["opC=2", "<none>=1", "opA=1"]);
}

#[test]
fn since_a_duration_counts_back_from_now() {
    let dir = tempdir();
    let now = chrono::Utc::now();
    let recent =
        (now - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let old =
        (now - chrono::Duration::days(10)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    std::fs::write(
        dir.join("t.jsonl"),
        [
            span(&recent, "api", Some("recentOp"), Some(200), "ok"),
            span(&old, "api", Some("oldOp"), Some(200), "ok"),
        ]
        .join("\n")
            + "\n",
    )
    .unwrap();
    let out = run_in(
        &dir,
        &["--since", "2d", "--group-by", "operation.id"],
        false,
    );
    assert_eq!(groups(&out), ["recentOp=1"]);
    let out = run_in(
        &dir,
        &["--since", "30d", "--group-by", "operation.id"],
        false,
    );
    assert_eq!(groups(&out), ["oldOp=1", "recentOp=1"]);
}

#[test]
fn cooccur_counts_distinct_operations_within_the_window() {
    let dir = trail();
    // Day 1: A@0:00, B@0:30, A@4:00. A-B pairs: (A0,B), (B,A4). A-A is not a pair.
    // Day 2: C and C only, and the filter span has no operation.
    let out = run_in(&dir, &["--cooccur", "5m"], false);
    assert_eq!(pairs(&out), ["opA+opB=2"]);
}

#[test]
fn a_narrow_window_drops_the_far_pair() {
    let dir = trail();
    let out = run_in(&dir, &["--cooccur", "60s"], false);
    assert_eq!(pairs(&out), ["opA+opB=1"]);
}

#[test]
fn pair_records_carry_the_field_and_window() {
    let dir = trail();
    let recs = records(&run_in(&dir, &["--cooccur", "5m"], false));
    assert_eq!(recs[0]["field"], "operation.id");
    assert_eq!(recs[0]["window_secs"], 300);
}

#[test]
fn cooccur_follows_group_by_when_both_are_given() {
    let dir = trail();
    let out = run_in(&dir, &["--group-by", "result", "--cooccur", "5m"], false);
    let recs = records(&out);
    // Groups come first, then pairs; the pairs are over the same field.
    assert_eq!(recs[0]["_kind"], "audit_group");
    assert_eq!(pairs(&out), ["http_error+ok=2"]);
}

#[test]
fn output_composes_with_the_other_stream_verbs() {
    let dir = trail();
    let first = run_in(&dir, &["--group-by", "operation.id"], false);
    let mut cmd = Command::cargo_bin("sidestep").unwrap();
    cmd.args(["rank", "--by", "key:asc"]);
    cmd.env("SIDESTEP_AUDIT", "off");
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), &first.stdout).unwrap();
    drop(child.stdin.take());
    let ranked = child.wait_with_output().unwrap();
    assert_eq!(groups(&ranked), ["<none>=1", "opA=2", "opB=1", "opC=2"]);
}

#[test]
fn bad_arguments_are_refused_with_no_output() {
    let dir = trail();
    for args in [
        &["--since", "yesterday"][..],
        &["--since", "5x"],
        &["--since", ""],
        &["--cooccur", "0s"],
        &["--cooccur", "soon"],
        &["--top", "0"],
        &["--group-by", ""],
        &["--group-by", "a..b"],
    ] {
        let out = run_in(&dir, args, false);
        assert!(!out.status.success(), "{args:?} must be refused");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn a_missing_trail_directory_is_an_error_naming_it() {
    let dir = trail().join("no-such-subdir");
    let out = run_in(&dir, &[], false);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no-such-subdir"));
}

#[test]
fn an_empty_window_says_so_on_stderr() {
    let dir = trail();
    let out = run_in(
        &dir,
        &["--since", "2030-01-01", "--group-by", "result"],
        false,
    );
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("0 spans"));
}

#[test]
fn help_says_it_reads_the_trail_and_makes_no_api_call() {
    let out = Command::cargo_bin("sidestep")
        .unwrap()
        .args(["audit", "query", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("makes no API call"), "{help}");
}

#[test]
fn emits_one_verb_audit_line_after_reading() {
    let dir = trail();
    let out = run_in(&dir, &["--group-by", "operation.id"], true);
    assert!(out.status.success());
    let mut own = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        for l in std::fs::read_to_string(entry.path()).unwrap().lines() {
            if let Ok(v) = serde_json::from_str::<Value>(l) {
                if v["verb_phase"] == "audit_query" {
                    own.push(v);
                }
            }
        }
    }
    assert_eq!(own.len(), 1, "one audit line per query invocation");
    let o = &own[0]["audit_query_outcome"];
    assert_eq!(own[0]["schema_version"], 2);
    assert_eq!(o["spans_read"], 6);
    assert_eq!(o["spans_selected"], 6);
    assert_eq!(o["emitted_count"], 4);
    assert_eq!(o["error_count"], 0);
    assert!(own[0].get("operation").is_none());
}
