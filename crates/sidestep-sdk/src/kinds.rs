//! The 9 `_kind` types for sidestep v0.1.
//!
//! Each kind binds:
//!   * a stable name (`detection`, `run`, …) — appears in `_kind`
//!   * a list operation (`operationId`) for `sidestep list <kind>`
//!   * an optional get-by-id operation for `sidestep get <kind> <id>`
//!   * the field that holds the primary key (for `id` semantics in
//!     downstream filters and ActionItem evidence joins)
//!   * the response-extraction strategy — the path in the response body
//!     that holds the array of items (some endpoints return a bare array,
//!     others wrap in `{ data: [...] }` etc.)
//!
//! Per `_kos/probes/brief-primitive-layer-v01.md` and finding-001.

use serde_json::Value;

/// Stable v0.1 kind names.
pub const KIND_RUN: &str = "run";
pub const KIND_DETECTION: &str = "detection";
pub const KIND_CHECK: &str = "check";
pub const KIND_POLICY: &str = "policy";
pub const KIND_RULE: &str = "rule";
pub const KIND_INCIDENT: &str = "incident";
pub const KIND_AUDIT_LOG: &str = "audit_log";
pub const KIND_REPO: &str = "repo";
pub const KIND_THREAT_INTEL: &str = "threat_intel";

/// All v0.1 kind names, in stable order.
pub const ALL_KINDS: &[&str] = &[
    KIND_RUN,
    KIND_DETECTION,
    KIND_CHECK,
    KIND_POLICY,
    KIND_RULE,
    KIND_INCIDENT,
    KIND_AUDIT_LOG,
    KIND_REPO,
    KIND_THREAT_INTEL,
];

/// Static metadata for one `_kind`.
#[derive(Debug, Clone)]
pub struct KindSpec {
    /// Stable name in the stream contract.
    pub name: &'static str,

    /// `operationId` to call for `sidestep list <kind>`. Some kinds have
    /// no first-class list endpoint — for v0.1 they're populated from
    /// adjacent endpoints (`incident` shares `getThreatIntelIncidents`)
    /// or marked unsupported.
    pub list_operation_id: Option<&'static str>,

    /// `operationId` for `sidestep get <kind> <id>`, when the spec
    /// exposes one.
    pub get_operation_id: Option<&'static str>,

    /// Field name in each item that carries the stable primary key.
    pub id_field: &'static str,

    /// Field name in each item that carries severity, when present.
    /// Used for the `severity-roll-up` enrichment.
    pub severity_field: Option<&'static str>,

    /// Field name in each item that carries the canonical timestamp
    /// (used by `--since` and the canonical adapter's `now` binding
    /// comparisons).
    pub primary_timestamp_field: Option<&'static str>,

    /// Spec path-parameter name that the kind's `id` binds to in
    /// `sidestep get <kind> <id>`. `None` when the kind has no
    /// get-by-id endpoint (or the endpoint takes no id-shaped path
    /// param). Other path params (owner, repo, …) are supplied via
    /// `--owner` / `--param`.
    pub id_path_param: Option<&'static str>,

    /// Field name on each record that `sidestep search <kind> <text>`
    /// matches against (case-insensitive substring). `None` means
    /// search isn't supported for this kind in v0.1 — operators
    /// compose `list | filter` instead.
    pub search_field: Option<&'static str>,
}

/// Look up a kind by its stream-contract name.
pub fn kind_spec(name: &str) -> Option<&'static KindSpec> {
    KIND_TABLE.iter().find(|k| k.name == name)
}

/// All v0.1 kind specs.
pub fn all_kinds() -> &'static [KindSpec] {
    KIND_TABLE
}

/// The static kind → operation table.
///
/// `incident` and `threat_intel` both surface from `getThreatIntelIncidents`;
/// the discriminator is which records the user asks for. `repo` has no
/// dedicated list endpoint in v0.1 of the StepSecurity spec — operators
/// derive repos from adjacent records (e.g., `enrich --with repo-owner`).
const KIND_TABLE: &[KindSpec] = &[
    KindSpec {
        name: KIND_RUN,
        list_operation_id: Some("getRunsDetails"),
        get_operation_id: Some("get_github_owner_repo_actions_runs_runid"),
        id_field: "id",
        severity_field: None,
        primary_timestamp_field: Some("triggered_at"),
        id_path_param: Some("runid"),
        search_field: Some("workflow_path"),
    },
    KindSpec {
        name: KIND_DETECTION,
        list_operation_id: Some("get_github_owner_actions_detections"),
        get_operation_id: None,
        id_field: "id",
        severity_field: Some("severity"),
        primary_timestamp_field: Some("created_at"),
        id_path_param: None,
        search_field: Some("detection_pattern"),
    },
    KindSpec {
        name: KIND_CHECK,
        list_operation_id: Some("get_github_owner_checks"),
        get_operation_id: Some("get_github_owner_repo_checks_head_sha"),
        id_field: "id",
        severity_field: None,
        primary_timestamp_field: Some("created_at"),
        id_path_param: Some("head_sha"),
        search_field: None,
    },
    KindSpec {
        name: KIND_POLICY,
        list_operation_id: Some("get_github_owner_actions_policies"),
        get_operation_id: None,
        id_field: "id",
        severity_field: Some("severity"),
        primary_timestamp_field: Some("last_evaluated_at"),
        id_path_param: None,
        search_field: Some("name"),
    },
    KindSpec {
        name: KIND_RULE,
        list_operation_id: Some("get_github_owner_actions_rules"),
        get_operation_id: None,
        id_field: "id",
        severity_field: Some("severity"),
        primary_timestamp_field: Some("created_at"),
        id_path_param: None,
        search_field: Some("pattern"),
    },
    KindSpec {
        name: KIND_INCIDENT,
        list_operation_id: Some("getThreatIntelIncidents"),
        get_operation_id: Some("getThreatIntelIncidentById"),
        id_field: "id",
        severity_field: Some("severity"),
        primary_timestamp_field: Some("first_seen"),
        id_path_param: Some("incidentId"),
        search_field: None,
    },
    KindSpec {
        name: KIND_AUDIT_LOG,
        list_operation_id: Some("get_customer_audit_logs"),
        get_operation_id: None,
        id_field: "id",
        severity_field: None,
        primary_timestamp_field: Some("ts"),
        id_path_param: None,
        search_field: Some("operation"),
    },
    KindSpec {
        name: KIND_REPO,
        list_operation_id: None,
        get_operation_id: None,
        id_field: "name",
        severity_field: None,
        primary_timestamp_field: None,
        id_path_param: None,
        search_field: Some("name"),
    },
    KindSpec {
        name: KIND_THREAT_INTEL,
        list_operation_id: Some("getThreatIntelIncidents"),
        get_operation_id: Some("getThreatIntelIncidentById"),
        id_field: "id",
        severity_field: Some("severity"),
        primary_timestamp_field: Some("first_seen"),
        id_path_param: Some("incidentId"),
        search_field: None,
    },
];

/// Extract the array of items from an API response body. Mirrors the
/// detection logic in `audit::count_items` so the audit-emitted
/// `items_returned` matches what the primitive actually streams.
pub fn extract_items(response: &Value) -> Option<&[Value]> {
    if let Some(arr) = response.as_array() {
        return Some(arr);
    }
    for key in [
        "items",
        "data",
        "results",
        "runs",
        "detections",
        "checks",
        "policies",
        "rules",
        "incidents",
        "audit_logs",
    ] {
        if let Some(arr) = response.get(key).and_then(|v| v.as_array()) {
            return Some(arr);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn nine_kinds_in_table() {
        assert_eq!(KIND_TABLE.len(), 9);
        assert_eq!(ALL_KINDS.len(), 9);
        for (a, b) in KIND_TABLE.iter().zip(ALL_KINDS.iter()) {
            assert_eq!(&a.name, b);
        }
    }

    #[test]
    fn lookup_known_kind() {
        let k = kind_spec("detection").expect("detection in table");
        assert_eq!(
            k.list_operation_id,
            Some("get_github_owner_actions_detections")
        );
        assert_eq!(k.severity_field, Some("severity"));
        assert_eq!(k.search_field, Some("detection_pattern"));
    }

    #[test]
    fn run_kind_has_runid_path_param() {
        let k = kind_spec("run").expect("run in table");
        assert_eq!(k.id_path_param, Some("runid"));
    }

    #[test]
    fn incident_and_threat_intel_share_id_path_param() {
        let i = kind_spec("incident").expect("incident");
        let t = kind_spec("threat_intel").expect("threat_intel");
        assert_eq!(i.id_path_param, Some("incidentId"));
        assert_eq!(t.id_path_param, Some("incidentId"));
    }

    #[test]
    fn lookup_unknown_kind() {
        assert!(kind_spec("nope").is_none());
    }

    #[test]
    fn extract_items_handles_bare_array() {
        let body = json!([{"id": "a"}, {"id": "b"}]);
        assert_eq!(extract_items(&body).unwrap().len(), 2);
    }

    #[test]
    fn extract_items_handles_wrapped_arrays() {
        let body = json!({"items": [{"id": "a"}]});
        assert_eq!(extract_items(&body).unwrap().len(), 1);
        let body = json!({"detections": [{"id": "a"}, {"id": "b"}]});
        assert_eq!(extract_items(&body).unwrap().len(), 2);
    }

    #[test]
    fn extract_items_returns_none_when_no_array() {
        let body = json!({"id": "single", "severity": "high"});
        assert!(extract_items(&body).is_none());
    }
}
