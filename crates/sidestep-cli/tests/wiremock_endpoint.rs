//! End-to-end integration tests against a wiremock mock server.
//!
//! Closes two loops at once:
//!   * the SDK base-URL override (`SIDESTEP_BASE_URL`) actually
//!     reaches the network layer, with path/query/header construction
//!     matching the OpenAPI spec.
//!   * the y7lq audit signal (`path_params_source.<param>`) flows
//!     end-to-end through the audit JSONL when owner is resolved via
//!     each of flag / env / config sources.
//!
//! Pattern: `#[tokio::test]` spins up a `MockServer`, mounts a `Mock`
//! with explicit method/path/query/header expectations, then runs the
//! `sidestep` CLI synchronously via `assert_cmd` with
//! `SIDESTEP_BASE_URL=<server.uri()>`. Mock expectations are verified
//! on `MockServer::drop` — failure to match raises a panic with the
//! actual requests received.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
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

fn read_audit_lines(dir: &PathBuf) -> Vec<Value> {
    let mut out = Vec::new();
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return out,
    };
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

/// API-shape lines (those carrying an `operation` block) — distinct
/// from verb-shape lines emitted by `filter` / `enrich`.
fn api_audit_lines(audit_dir: &PathBuf) -> Vec<Value> {
    read_audit_lines(audit_dir)
        .into_iter()
        .filter(|v| v.get("operation").is_some())
        .collect()
}

fn cmd() -> Command {
    Command::cargo_bin("sidestep").expect("sidestep binary built")
}

/// Common env scrub — wipe owner/customer/config so each test sees a
/// clean slate.
fn scrub_resolution_env(c: &mut Command) {
    c.env_remove("SIDESTEP_OWNER");
    c.env_remove("SIDESTEP_CUSTOMER");
    c.env_remove("SIDESTEP_CONFIG");
}

fn detection_response_body() -> Value {
    json!({
        "detections": [
            {
                "id": "det_001",
                "severity": "critical",
                "status": "open",
                "created_at": "2026-04-29T14:23:11Z",
                "repo": {"owner": "arcaven", "name": "infra"},
            },
            {
                "id": "det_002",
                "severity": "high",
                "status": "open",
                "created_at": "2026-04-30T08:11:42Z",
                "repo": {"owner": "arcaven", "name": "web-api"},
            },
        ]
    })
}

#[tokio::test]
async fn list_detections_routes_owner_flag_into_url_path() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/detections"))
        .and(query_param("detection_id", "New-Outbound-Network-Call"))
        .and(header("authorization", "Bearer fake-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detection_response_body()))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");

    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args([
            "list",
            "detection",
            "--owner",
            "arcaven",
            "--param",
            "detection_id=New-Outbound-Network-Call",
        ])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "list failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = std::str::from_utf8(&out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected 2 records, got {lines:?}");
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        first.get("_kind").and_then(Value::as_str),
        Some("detection")
    );
    assert_eq!(first.get("id").and_then(Value::as_str), Some("det_001"));

    let api = api_audit_lines(&audit_dir);
    assert_eq!(api.len(), 1, "expected one API audit line, got {api:?}");
    let pps = api[0]
        .get("path_params_source")
        .expect("path_params_source emitted");
    assert_eq!(
        pps.get("owner").and_then(Value::as_str),
        Some("flag"),
        "owner came from --owner flag, audit must record `flag`"
    );
}

#[tokio::test]
async fn list_detections_owner_resolves_from_env() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github/from-env/actions/detections"))
        .and(query_param("detection_id", "Reverse-Shell"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detection_response_body()))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");

    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["list", "detection", "--param", "detection_id=Reverse-Shell"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_OWNER", "from-env")
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let api = api_audit_lines(&audit_dir);
    assert_eq!(api.len(), 1);
    assert_eq!(
        api[0]["path_params_source"]["owner"].as_str(),
        Some("env"),
        "owner came from SIDESTEP_OWNER, audit must record `env`"
    );
}

#[tokio::test]
async fn list_detections_owner_resolves_from_config() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github/from-config/actions/detections"))
        .and(query_param("detection_id", "Privileged-Container"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detection_response_body()))
        .expect(1)
        .mount(&server)
        .await;

    let cfg_dir = tempdir("cfg");
    let cfg = cfg_dir.join("config.toml");
    std::fs::write(
        &cfg,
        r#"
[default]
owner = "from-config"
"#,
    )
    .unwrap();

    let audit_dir = tempdir("audit");

    let mut c = cmd();
    // Don't scrub_resolution_env — we want SIDESTEP_CONFIG set.
    c.env_remove("SIDESTEP_OWNER");
    c.env_remove("SIDESTEP_CUSTOMER");
    let out = c
        .args([
            "list",
            "detection",
            "--param",
            "detection_id=Privileged-Container",
        ])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_CONFIG", &cfg)
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let api = api_audit_lines(&audit_dir);
    assert_eq!(api.len(), 1);
    assert_eq!(
        api[0]["path_params_source"]["owner"].as_str(),
        Some("config"),
        "owner came from [default] in config, audit must record `config`. \
         This is the y7lq loop closer — proves the source signal flows \
         end-to-end through the audit JSONL."
    );
}

#[tokio::test]
async fn list_detections_flag_overrides_env_and_config() {
    let server = MockServer::start().await;
    // The expected URL is the FLAG value, not env or config.
    Mock::given(method("GET"))
        .and(path("/github/from-flag/actions/detections"))
        .and(query_param("detection_id", "Secret-In-Build-Log"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detection_response_body()))
        .expect(1)
        .mount(&server)
        .await;

    let cfg_dir = tempdir("cfg");
    let cfg = cfg_dir.join("config.toml");
    std::fs::write(
        &cfg,
        r#"
[default]
owner = "from-config"
"#,
    )
    .unwrap();

    let audit_dir = tempdir("audit");

    let out = cmd()
        .args([
            "list",
            "detection",
            "--owner",
            "from-flag",
            "--param",
            "detection_id=Secret-In-Build-Log",
        ])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_OWNER", "from-env")
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_CUSTOMER")
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let api = api_audit_lines(&audit_dir);
    assert_eq!(api.len(), 1);
    assert_eq!(
        api[0]["path_params_source"]["owner"].as_str(),
        Some("flag"),
        "flag is the highest-precedence layer; chain order broken"
    );
}

#[tokio::test]
async fn list_handles_bare_array_response_shape() {
    // Some endpoints return a top-level array rather than the wrapped
    // `{key: [...]}` shape — `extract_items` accepts either. Exercise
    // the bare-array path over the wire to lock the contract in place.
    let server = MockServer::start().await;
    let body = json!([
        {"id": "det_a", "severity": "low", "status": "open"},
        {"id": "det_b", "severity": "info", "status": "resolved"},
        {"id": "det_c", "severity": "medium", "status": "open"},
    ]);
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/detections"))
        .and(query_param("detection_id", "Suspicious-Process-Call"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");

    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args([
            "list",
            "detection",
            "--owner",
            "arcaven",
            "--param",
            "detection_id=Suspicious-Process-Call",
        ])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = std::str::from_utf8(&out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        3,
        "bare-array response must yield one record per element, got {lines:?}"
    );
}

#[tokio::test]
async fn get_run_routes_id_path_param() {
    // Exercises a multi-path-param endpoint:
    // GET /github/{owner}/{repo}/actions/runs/{runid}
    let server = MockServer::start().await;
    let body = json!({
        "id": "run_alpha",
        "status": "failed",
        "branch": "main",
        "head_sha": "a1b2c3d4e5f6",
        "repo": {"owner": "arcaven", "name": "infra"},
    });
    Mock::given(method("GET"))
        .and(path("/github/arcaven/infra/actions/runs/run_alpha"))
        .and(header("authorization", "Bearer fake-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");

    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args([
            "get",
            "run",
            "run_alpha",
            "--owner",
            "arcaven",
            "--repo",
            "infra",
        ])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = std::str::from_utf8(&out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "get emits one record");
    let rec: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(rec.get("_kind").and_then(Value::as_str), Some("run"));
    assert_eq!(rec.get("id").and_then(Value::as_str), Some("run_alpha"));
}

// ---------------------------------------------------------------------
// Pagination (aae-orc-u7hy): list follows next_token to exhaustion.
// ---------------------------------------------------------------------

#[tokio::test]
async fn list_runs_follows_next_token_across_pages() {
    let server = MockServer::start().await;

    // Page 2 — only matches when the continuation token is echoed back.
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/runs"))
        .and(query_param("next_token", "t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_workflow_runs": 3,
            "workflow_runs": [{"id": "r3"}],
            "next_token": "",
            "has_more": false,
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Page 1 — first request carries no token.
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/runs"))
        .and(wiremock::matchers::query_param_is_missing("next_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total_workflow_runs": 3,
            "workflow_runs": [{"id": "r1"}, {"id": "r2"}],
            "next_token": "t1",
            "has_more": true,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["list", "run", "--owner", "arcaven"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = std::str::from_utf8(&out.stdout).unwrap();
    let ids: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            serde_json::from_str::<Value>(l)
                .unwrap()
                .get("id")
                .and_then(Value::as_str)
                .unwrap()
                .to_string()
        })
        .map(|s| Box::leak(s.into_boxed_str()) as &str)
        .collect();
    assert_eq!(ids, vec!["r1", "r2", "r3"], "all pages emitted in order");

    // Each page is a real API call: two audit lines, both audited.
    let api_lines = api_audit_lines(&audit_dir);
    assert_eq!(api_lines.len(), 2, "one audit line per page");
}

#[tokio::test]
async fn list_limit_stops_pagination_early() {
    let server = MockServer::start().await;

    // Page 1 returns a token, but --limit 2 is satisfied by page 1 —
    // page 2 must never be requested (expect(0) enforced on drop).
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/runs"))
        .and(query_param("next_token", "t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "workflow_runs": [{"id": "r3"}],
            "next_token": "",
        })))
        .expect(0)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/runs"))
        .and(wiremock::matchers::query_param_is_missing("next_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "workflow_runs": [{"id": "r1"}, {"id": "r2"}],
            "next_token": "t1",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["list", "run", "--owner", "arcaven", "--limit", "2"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::str::from_utf8(&out.stdout)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .count(),
        2
    );
}

#[tokio::test]
async fn list_detections_unwraps_nested_data_envelope() {
    // detections wrap the collection inside a `data` OBJECT
    // (`{"data": {"detections": [...], "next_token": ""}}`) — the shape
    // extract_items missed before finding-007's release-prep pass.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/detections"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "detections": [
                    {"id": "d1", "severity": "critical"},
                    {"id": "d2", "severity": "low"},
                ],
                "has_more": false,
                "next_token": "",
                "count": 2,
            }
        })))
        .expect(1)
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
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = std::str::from_utf8(&out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "records unwrapped from nested data object");
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first.get("id").and_then(Value::as_str), Some("d1"));
}

// ---------------------------------------------------------------------
// Resolution chain on the `api` passthrough (F3 mining proposal #1).
// ---------------------------------------------------------------------

#[tokio::test]
async fn api_passthrough_resolves_owner_from_env() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/security-summary"))
        .and(header("authorization", "Bearer fake-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"score": 7})))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["api", "getSecuritySummary"])
        .env("SIDESTEP_OWNER", "arcaven")
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "api passthrough with env owner failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let api_lines = api_audit_lines(&audit_dir);
    assert_eq!(api_lines.len(), 1);
    assert_eq!(
        api_lines[0]
            .get("path_params_source")
            .and_then(|s| s.get("owner"))
            .and_then(Value::as_str),
        Some("env"),
        "audit records the chain source for the api verb"
    );
}

#[tokio::test]
async fn api_passthrough_explicit_param_beats_chain() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github/explicit-org/actions/security-summary"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"score": 3})))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["api", "getSecuritySummary", "--param", "owner=explicit-org"])
        .env("SIDESTEP_OWNER", "env-org-must-lose")
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let api_lines = api_audit_lines(&audit_dir);
    assert_eq!(
        api_lines[0]
            .get("path_params_source")
            .and_then(|s| s.get("owner"))
            .and_then(Value::as_str),
        Some("flag"),
        "explicit --param records as flag source"
    );
}

#[test]
fn api_passthrough_without_owner_names_the_chain() {
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    // Point config at an empty tempdir so no [default] owner leaks in.
    let cfg = tempdir("cfg").join("config.toml");
    let out = c
        .args(["api", "getSecuritySummary"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .output()
        .unwrap();
    assert!(!out.status.success(), "must fail without owner");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for needle in [
        "--owner",
        "SIDESTEP_OWNER",
        "auth login --owner",
        "config set owner",
    ] {
        assert!(
            stderr.contains(needle),
            "chain error must name `{needle}`; got: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------
// First-class --type/--status filters (aae-orc-onef).
// ---------------------------------------------------------------------

#[tokio::test]
async fn list_detections_status_flag_maps_to_query_param() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github/arcaven/actions/detections"))
        .and(query_param("status", "new"))
        .and(query_param("detection_id", "Domain-Blocked"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detection_response_body()))
        .expect(1)
        .mount(&server)
        .await;

    let audit_dir = tempdir("audit");
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args([
            "list",
            "detection",
            "--owner",
            "arcaven",
            "--status",
            "new",
            "--type",
            "Domain-Blocked",
        ])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", server.uri())
        .env("SIDESTEP_AUDIT_DIR", &audit_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn list_detections_invalid_status_fails_before_network_with_enum() {
    // No mock server at all — an invalid enum value must never reach
    // the network. The error names the full expected set.
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args([
            "list",
            "detection",
            "--owner",
            "arcaven",
            "--status",
            "open",
        ])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    for needle in ["--status", "new", "suppressed", "resolved"] {
        assert!(stderr.contains(needle), "missing `{needle}` in: {stderr}");
    }
}

#[test]
fn list_rule_rejects_status_flag_as_not_applicable() {
    let mut c = cmd();
    scrub_resolution_env(&mut c);
    let out = c
        .args(["list", "rule", "--owner", "arcaven", "--status", "new"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--status is not applicable"),
        "got: {stderr}"
    );
    assert!(
        stderr.contains("ops show"),
        "should point at discovery: {stderr}"
    );
}
