//! `--since` against the shapes the API returns (issue 54).
//!
//! `list detection --since` failed on every window because the kind named
//! `created_at` as its time field and the records carry `timestamp`, and
//! `timestamp` is epoch seconds as a string, which the predicate could not
//! compare either. These tests serve records in the shapes seen from the
//! live API through a mock server: detections with a string of epoch
//! seconds, runs with an integer, rules with a string, incidents with an
//! RFC 3339 string. Every record here is synthetic.
//!
//! A filter that cannot be evaluated must fail the command. It must never
//! read as an empty list: an empty result is what a caller trusts.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::cargo::CommandCargoExt;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const HOUR: i64 = 3600;

fn rfc3339(secs_ago: i64) -> String {
    chrono::DateTime::from_timestamp(now() - secs_ago, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

async fn serve(route: &str, body: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

fn list(server: &MockServer, args: &[&str]) -> std::process::Output {
    let mut c = Command::cargo_bin("sidestep").expect("sidestep binary");
    c.env_remove("SIDESTEP_OWNER")
        .env_remove("SIDESTEP_CUSTOMER")
        .env_remove("SIDESTEP_CONFIG")
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_AUDIT", "off")
        .env("SIDESTEP_BASE_URL", server.uri())
        .arg("list")
        .args(args)
        .args(["--owner", "arcaven"]);
    c.output().expect("output")
}

fn ids(out: &std::process::Output) -> Vec<String> {
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

/// Detections as the API sends them: `timestamp` is a string of epoch seconds.
fn detections() -> Value {
    let rec = |id: &str, ago: i64| {
        json!({
            "id": id,
            "severity": "high",
            "timestamp": (now() - ago).to_string(),
            "id_timestamp": format!("Domain-Blocked-{}", now() - ago),
        })
    };
    json!({"data": {
        "detections": [rec("det_new", HOUR), rec("det_mid", 48 * HOUR), rec("det_old", 1000 * HOUR)],
        "has_more": false,
        "next_token": "",
    }})
}

const DETECTIONS: &str = "/github/arcaven/actions/detections";

#[tokio::test]
async fn detection_since_keeps_records_inside_the_window() {
    let server = serve(DETECTIONS, detections()).await;
    let out = list(&server, &["detection", "--since", "24h"]);
    assert_eq!(ids(&out), ["det_new"]);
}

#[tokio::test]
async fn detection_since_a_wide_window_keeps_them_all() {
    // The issue's repro: a wide window failed the same way as a narrow one.
    let server = serve(DETECTIONS, detections()).await;
    let out = list(&server, &["detection", "--since", "8760h"]);
    assert_eq!(ids(&out), ["det_new", "det_mid", "det_old"]);
}

#[tokio::test]
async fn detection_since_a_middle_window_cuts_between_records() {
    let server = serve(DETECTIONS, detections()).await;
    let out = list(&server, &["detection", "--since", "100h"]);
    assert_eq!(ids(&out), ["det_new", "det_mid"]);
}

#[tokio::test]
async fn a_filter_that_cannot_run_fails_and_does_not_read_as_empty() {
    // No record carries the time field. The command must exit nonzero and
    // name the field; zero records on stdout alone would read as "none".
    let body = json!({"data": {"detections": [{"id": "det_x", "severity": "high"}],
                               "has_more": false, "next_token": ""}});
    let server = serve(DETECTIONS, body).await;
    let out = list(&server, &["detection", "--since", "24h"]);
    assert!(!out.status.success(), "must fail, not return an empty list");
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("timestamp"),
        "stderr must name the field: {err}"
    );
}

#[tokio::test]
async fn a_time_field_that_is_not_a_time_fails_the_command() {
    let body = json!({"data": {"detections": [{"id": "det_x", "timestamp": "yesterday"}],
                               "has_more": false, "next_token": ""}});
    let server = serve(DETECTIONS, body).await;
    let out = list(&server, &["detection", "--since", "24h"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[tokio::test]
async fn run_since_reads_the_integer_start_time() {
    let rec = |id: &str, ago: i64| json!({"id": id, "start_time_utc": now() - ago});
    let body = json!({"workflow_runs": [rec("run_new", HOUR), rec("run_old", 1000 * HOUR)],
                      "next_token": "", "has_more": false});
    let server = serve("/github/arcaven/actions/runs", body).await;
    let out = list(&server, &["run", "--since", "24h"]);
    assert_eq!(ids(&out), ["run_new"]);
}

#[tokio::test]
async fn rule_since_reads_created_on() {
    let rec = |id: &str, ago: i64| json!({"id": id, "created_on": (now() - ago).to_string()});
    let body = json!({"rules": [rec("rule_new", HOUR), rec("rule_old", 1000 * HOUR)]});
    let server = serve("/github/arcaven/actions/rules", body).await;
    let out = list(&server, &["rule", "--since", "24h"]);
    assert_eq!(ids(&out), ["rule_new"]);
}

#[tokio::test]
async fn incident_since_reads_created_at() {
    let rec = |id: &str, ago: i64| json!({"id": id, "created_at": rfc3339(ago)});
    let body = json!({"detections": [rec("inc_new", HOUR), rec("inc_old", 1000 * HOUR)]});
    let server = serve("/github/arcaven/threat-intel/incidents", body).await;
    let out = list(&server, &["incident", "--since", "24h"]);
    assert_eq!(ids(&out), ["inc_new"]);
}

#[tokio::test]
async fn check_since_keeps_working_on_created_at() {
    let rec = |id: &str, ago: i64| json!({"id": id, "created_at": rfc3339(ago)});
    let body = json!({"checks": [rec("chk_new", HOUR), rec("chk_old", 1000 * HOUR)]});
    let server = serve("/github/arcaven/checks", body).await;
    let out = list(&server, &["check", "--since", "24h"]);
    assert_eq!(ids(&out), ["chk_new"]);
}

#[tokio::test]
async fn policy_has_no_time_field_so_since_is_refused() {
    // The policy records carry no time at all, so no field can be named.
    let server = serve("/github/arcaven/actions/policies", json!([])).await;
    let out = list(&server, &["policy", "--since", "24h"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no primary timestamp field"));
}
