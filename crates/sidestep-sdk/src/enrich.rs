//! Enrichment recipes for `sidestep enrich --with <recipe>`.
//!
//! v0.1 ships three recipes per finding-001:
//!
//! * `policy-context` — for each rule record, attach its parent policy
//!   as a `policy` field. Orphan rules (no matching policy in the
//!   auxiliary set) get `policy: null`. Non-rule records pass through
//!   unchanged. Requires an auxiliary stream of policy records.
//!
//! * `severity-roll-up` — for every record, populate `severity_rollup`.
//!   When `--policies` is supplied and the record is a rule, the
//!   rollup is `max(rule.severity, parent_policy.severity)`. Without
//!   `--policies`, the rollup is just the record's own severity (copy-
//!   rename so downstream rank predicates don't have to special-case
//!   missing-vs-present).
//!
//! * `repo-owner` — for any record with `repo.owner`, hoist a top-level
//!   `_repo_owner` field. Records without `repo.owner` pass through
//!   unchanged. v0.1 stops at the hoist; team-membership join is a
//!   v0.2 enrichment that needs an external mapping source.
//!
//! Recipe machinery: each recipe is a function `Record -> Record`
//! parameterised by an [`EnrichmentContext`] that carries the
//! pre-built auxiliary lookups. Building the context is a one-time
//! cost per `enrich` invocation; transformation is per-record.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::error::{Result, SidestepError};
use crate::stream::Record;

/// Recipe selector. Stable string names match the CLI `--with` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipe {
    PolicyContext,
    SeverityRollUp,
    RepoOwner,
}

impl Recipe {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "policy-context" => Some(Self::PolicyContext),
            "severity-roll-up" => Some(Self::SeverityRollUp),
            "repo-owner" => Some(Self::RepoOwner),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyContext => "policy-context",
            Self::SeverityRollUp => "severity-roll-up",
            Self::RepoOwner => "repo-owner",
        }
    }
}

/// Auxiliary lookups used by recipes. Built once per enrichment
/// invocation, then reused per record.
#[derive(Default, Debug)]
pub struct EnrichmentContext {
    /// Policy records indexed by `id`. Populated when the user passes
    /// `--policies <FILE>` (or, in a future revision, when enrich
    /// auto-fetches policies).
    pub policies_by_id: HashMap<String, Record>,
}

impl EnrichmentContext {
    /// Build a context from a list of policy records. Records with no
    /// `id` field, or whose id is not a string, are skipped.
    pub fn with_policies<I>(policies: I) -> Self
    where
        I: IntoIterator<Item = Record>,
    {
        let mut by_id = HashMap::new();
        for p in policies {
            if let Some(id) = p.get("id").and_then(Value::as_str) {
                by_id.insert(id.to_string(), p);
            }
        }
        Self {
            policies_by_id: by_id,
        }
    }

    pub fn validate_for(&self, recipe: Recipe) -> Result<()> {
        match recipe {
            Recipe::PolicyContext => {
                if self.policies_by_id.is_empty() {
                    return Err(SidestepError::InvalidParam(
                        "--with policy-context".into(),
                        "requires --policies <FILE> with at least one policy record".into(),
                    ));
                }
            }
            Recipe::SeverityRollUp | Recipe::RepoOwner => {}
        }
        Ok(())
    }
}

/// Apply one recipe to one record. Pure: same input ↔ same output.
pub fn apply(recipe: Recipe, record: Record, ctx: &EnrichmentContext) -> Record {
    match recipe {
        Recipe::PolicyContext => apply_policy_context(record, ctx),
        Recipe::SeverityRollUp => apply_severity_rollup(record, ctx),
        Recipe::RepoOwner => apply_repo_owner(record),
    }
}

fn apply_policy_context(mut record: Record, ctx: &EnrichmentContext) -> Record {
    if record.kind != "rule" {
        return record;
    }
    let parent = record
        .get("policy_id")
        .and_then(Value::as_str)
        .and_then(|pid| ctx.policies_by_id.get(pid));
    let attached = match parent {
        Some(p) => policy_summary(p),
        None => Value::Null,
    };
    record.fields.insert("policy".to_string(), attached);
    record
}

fn apply_severity_rollup(mut record: Record, ctx: &EnrichmentContext) -> Record {
    let own = record
        .get("severity")
        .and_then(Value::as_str)
        .map(str::to_string);
    let parent_severity = if record.kind == "rule" {
        record
            .get("policy_id")
            .and_then(Value::as_str)
            .and_then(|pid| ctx.policies_by_id.get(pid))
            .and_then(|p| p.get("severity"))
            .and_then(Value::as_str)
            .map(str::to_string)
    } else {
        None
    };

    let rollup = match (own.as_deref(), parent_severity.as_deref()) {
        (Some(a), Some(b)) => max_severity(a, b).map(str::to_string),
        (Some(a), None) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    };

    let value = match rollup {
        Some(s) => Value::String(s),
        None => Value::Null,
    };
    record.fields.insert("severity_rollup".to_string(), value);
    record
}

fn apply_repo_owner(mut record: Record) -> Record {
    if let Some(owner) = record
        .get("repo")
        .and_then(|v| v.get("owner"))
        .and_then(Value::as_str)
    {
        record
            .fields
            .insert("_repo_owner".to_string(), Value::String(owner.to_string()));
    }
    record
}

/// Reduce a policy record to the summary attached by `policy-context`.
/// Trims to the small set of fields downstream filters and emit
/// templates actually use; keeps the enriched stream compact.
fn policy_summary(p: &Record) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(id) = p.get("id") {
        out.insert("id".into(), id.clone());
    }
    if let Some(name) = p.get("name") {
        out.insert("name".into(), name.clone());
    }
    if let Some(sev) = p.get("severity") {
        out.insert("severity".into(), sev.clone());
    }
    if let Some(repos) = p.get("attached_repos") {
        out.insert("attached_repos".into(), repos.clone());
    }
    Value::Object(out)
}

/// Severity ordering matches the recipe scripts in `examples/recipes/`:
/// critical > high > medium > low > info. Unknown values rank lower
/// than any known value (caller falls back to the other operand).
fn severity_rank(s: &str) -> Option<u8> {
    match s {
        "critical" => Some(4),
        "high" => Some(3),
        "medium" => Some(2),
        "low" => Some(1),
        "info" => Some(0),
        _ => None,
    }
}

fn max_severity<'a>(a: &'a str, b: &'a str) -> Option<&'a str> {
    match (severity_rank(a), severity_rank(b)) {
        (Some(ra), Some(rb)) if ra >= rb => Some(a),
        (Some(_), Some(_)) => Some(b),
        (Some(_), None) => Some(a),
        (None, Some(_)) => Some(b),
        (None, None) => None,
    }
}

/// Helper for tests and CLI: ergonomic constructor for a synthetic
/// policy record (used by tests + recipe demos).
#[doc(hidden)]
pub fn synthetic_policy(id: &str, name: &str, severity: &str) -> Record {
    Record::wrap(
        "policy",
        crate::stream::SourceRef {
            operation_id: "synthetic".into(),
            response_index: 0,
            fetched_at: chrono::Utc::now(),
            trace_ref: None,
        },
        json!({
            "id": id,
            "name": name,
            "severity": severity,
            "attached_repos": [],
        }),
    )
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::stream::SourceRef;

    fn rule(id: &str, policy_id: Option<&str>, severity: &str) -> Record {
        let mut body = json!({"id": id, "severity": severity});
        if let Some(p) = policy_id {
            body["policy_id"] = json!(p);
        }
        Record::wrap(
            "rule",
            SourceRef {
                operation_id: "op".into(),
                response_index: 0,
                fetched_at: Utc::now(),
                trace_ref: None,
            },
            body,
        )
    }

    fn detection(id: &str, severity: &str, repo_owner: Option<&str>) -> Record {
        let mut body = json!({"id": id, "severity": severity, "status": "open"});
        if let Some(o) = repo_owner {
            body["repo"] = json!({"owner": o, "name": "marvel"});
        }
        Record::wrap(
            "detection",
            SourceRef {
                operation_id: "op".into(),
                response_index: 0,
                fetched_at: Utc::now(),
                trace_ref: None,
            },
            body,
        )
    }

    #[test]
    fn recipe_parse_round_trip() {
        for r in [
            Recipe::PolicyContext,
            Recipe::SeverityRollUp,
            Recipe::RepoOwner,
        ] {
            assert_eq!(Recipe::parse(r.as_str()), Some(r));
        }
        assert_eq!(Recipe::parse("nope"), None);
    }

    #[test]
    fn policy_context_attaches_parent_to_rule() {
        let ctx = EnrichmentContext::with_policies([synthetic_policy("pol_1", "egress", "high")]);
        let r = rule("rule_1", Some("pol_1"), "medium");
        let enriched = apply(Recipe::PolicyContext, r, &ctx);
        let policy = enriched.get("policy").expect("policy attached");
        assert_eq!(policy.get("id").and_then(Value::as_str), Some("pol_1"));
        assert_eq!(policy.get("severity").and_then(Value::as_str), Some("high"));
    }

    #[test]
    fn policy_context_marks_orphan_rule_with_null() {
        let ctx = EnrichmentContext::with_policies([synthetic_policy("pol_1", "egress", "high")]);
        let r = rule("rule_orphan", Some("pol_999"), "medium");
        let enriched = apply(Recipe::PolicyContext, r, &ctx);
        assert_eq!(enriched.get("policy"), Some(&Value::Null));
    }

    #[test]
    fn policy_context_passes_through_non_rules() {
        let ctx = EnrichmentContext::with_policies([synthetic_policy("pol_1", "egress", "high")]);
        let d = detection("det_1", "high", Some("arcaven"));
        let enriched = apply(Recipe::PolicyContext, d, &ctx);
        assert!(enriched.get("policy").is_none());
    }

    #[test]
    fn severity_rollup_takes_max_of_rule_and_parent() {
        let ctx =
            EnrichmentContext::with_policies([synthetic_policy("pol_1", "egress", "critical")]);
        let r = rule("rule_1", Some("pol_1"), "low");
        let enriched = apply(Recipe::SeverityRollUp, r, &ctx);
        assert_eq!(
            enriched.get("severity_rollup").and_then(Value::as_str),
            Some("critical")
        );
    }

    #[test]
    fn severity_rollup_falls_back_to_own_severity_without_parent() {
        let ctx = EnrichmentContext::default();
        let d = detection("det_1", "high", None);
        let enriched = apply(Recipe::SeverityRollUp, d, &ctx);
        assert_eq!(
            enriched.get("severity_rollup").and_then(Value::as_str),
            Some("high")
        );
    }

    #[test]
    fn severity_rollup_handles_missing_severity() {
        let ctx = EnrichmentContext::default();
        let r = Record::wrap(
            "audit_log",
            SourceRef {
                operation_id: "op".into(),
                response_index: 0,
                fetched_at: Utc::now(),
                trace_ref: None,
            },
            json!({"id": "aud_1", "operation": "x"}),
        );
        let enriched = apply(Recipe::SeverityRollUp, r, &ctx);
        assert_eq!(enriched.get("severity_rollup"), Some(&Value::Null));
    }

    #[test]
    fn repo_owner_hoists_top_level_field() {
        let d = detection("det_1", "high", Some("arcaven"));
        let enriched = apply(Recipe::RepoOwner, d, &EnrichmentContext::default());
        assert_eq!(
            enriched.get("_repo_owner").and_then(Value::as_str),
            Some("arcaven")
        );
    }

    #[test]
    fn repo_owner_passes_through_records_without_repo() {
        let r = rule("rule_1", Some("pol_1"), "high");
        let enriched = apply(Recipe::RepoOwner, r, &EnrichmentContext::default());
        assert!(enriched.get("_repo_owner").is_none());
    }

    #[test]
    fn validate_policy_context_requires_policies() {
        let empty = EnrichmentContext::default();
        assert!(empty.validate_for(Recipe::PolicyContext).is_err());
        let nonempty =
            EnrichmentContext::with_policies([synthetic_policy("pol_1", "egress", "high")]);
        assert!(nonempty.validate_for(Recipe::PolicyContext).is_ok());
    }

    #[test]
    fn max_severity_handles_unknown_values() {
        assert_eq!(max_severity("critical", "high"), Some("critical"));
        assert_eq!(max_severity("low", "info"), Some("low"));
        assert_eq!(max_severity("info", "info"), Some("info"));
        // Unknown loses to known
        assert_eq!(max_severity("unknown", "high"), Some("high"));
        // Both unknown returns None
        assert_eq!(max_severity("foo", "bar"), None);
    }
}
