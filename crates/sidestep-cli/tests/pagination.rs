//! End-to-end pagination integration tests (aae-orc-r4pt).
//!
//! The P1 defect: paginated list endpoints silently truncate at one
//! page — a response advertises a continuation cursor (`next_token`)
//! that never gets consumed, so a caller walking pages gets an
//! under-count and cannot tell the listing was incomplete. For a
//! security-inventory tool that is the worst failure mode: concluding
//! "not present" from a truncated page.
//!
//! Two behaviours are pinned here:
//!   * a cursor the client cannot advance (repeated token, unaccepted
//!     param, page cap) must produce a LOUD stderr warning — never a
//!     silent truncation.
//!   * a well-behaved multi-page endpoint must be followed to
//!     exhaustion, the cursor advancing across distinct tokens, with no
//!     false truncation warning.
//!
//! Pattern mirrors `wiremock_endpoint.rs`: a `MockServer` with mounted
//! `Mock`s, the `sidestep` CLI run via `assert_cmd` with
//! `SIDESTEP_BASE_URL` pointed at the mock. Fixtures are synthetic.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir(prefix: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = TEMPDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "sidestep-{prefix}-{}-{n}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cmd() -> Command {
    Command::cargo_bin("sidestep").expect("sidestep binary built")
}

fn scrub_resolution_env(c: &mut Command) {
    c.env_remove("SIDESTEP_OWNER");
    c.env_remove("SIDESTEP_CUSTOMER");
    c.env_remove("SIDESTEP_CONFIG");
}

fn detections_page(ids: &[&str], next_token: &str) -> Value {
    let items: Vec<Value> = ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "severity": "high",
                "status": "open",
                "created_at": "2026-04-30T08:11:42Z",
                "repo": {"owner": "arcaven", "name": "web-api"},
            })
        })
        .collect();
    json!({ "detections": items, "next_token": next_token, "has_more": !next_token.is_empty() })
}

/// The ticket's exact scenario: the server returns the same page and
/// the same `next_token` every time, so the cursor never advances. The
/// client must NOT silently return a truncated list — it must warn.
#[tokio::test]
async fn stuck_cursor_warns_instead_of_silently_truncating() {
    let server = MockServer::start().await;
    // Every request to this endpoint gets the same non-empty cursor.
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/detections"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(detections_page(&["det_001", "det_002"], "STUCK")),
        )
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["list", "detection", "--owner", "arcaven"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();

    // The command still succeeds — truncation is surfaced, not fatal.
    assert!(
        out.status.success(),
        "list should succeed with a warning, not fail: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("results may be incomplete"),
        "a stuck/never-advancing cursor must warn about incomplete results, \
         so truncation is never silent (aae-orc-r4pt); stderr was: {stderr:?}"
    );
}

/// A well-behaved multi-page endpoint: three pages joined by distinct
/// cursors, the last with an empty token. All rows must be emitted, the
/// cursor must advance across pages, and there must be no false
/// truncation warning.
#[tokio::test]
async fn pagination_advances_through_all_pages_without_warning() {
    let server = MockServer::start().await;
    let ep = "/github/arcaven/actions/detections";

    // wiremock returns the FIRST mounted mock whose matchers all pass,
    // so the specific cursor mocks are mounted before the general
    // page-1 mock (which matches any request to this path).
    //
    // Page 2 (cursor P2 -> distinct rows, next cursor P3).
    Mock::given(method("GET"))
        .and(path(ep))
        .and(query_param("next_token", "P2"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(detections_page(&["det_003", "det_004"], "P3")),
        )
        .mount(&server)
        .await;
    // Page 3 (cursor P3 -> last row, empty token terminates the walk).
    Mock::given(method("GET"))
        .and(path(ep))
        .and(query_param("next_token", "P3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detections_page(&["det_005"], "")))
        .mount(&server)
        .await;
    // Page 1 (first request carries no cursor). Mounted last as the
    // fallback for the cursorless opening request.
    Mock::given(method("GET"))
        .and(path(ep))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(detections_page(&["det_001", "det_002"], "P2")),
        )
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["list", "detection", "--owner", "arcaven"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "multi-page list failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let ids: Vec<String> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v.get("id").and_then(Value::as_str).unwrap().to_string()
        })
        .collect();
    assert_eq!(
        ids,
        vec!["det_001", "det_002", "det_003", "det_004", "det_005"],
        "all three pages must be fetched and the cursor advanced across distinct tokens"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("results may be incomplete"),
        "a clean end-of-listing (empty cursor) must not warn; stderr was: {stderr:?}"
    );
}
