//! CEL adapter for `sidestep filter --where '<CEL>'`.
//!
//! Implements the canonical adapter rules from finding-001:
//!
//! 1. `*_at` fields parsed to `Value::Timestamp` at ingest. Strings that
//!    do not parse as RFC 3339 stay as strings.
//! 2. Absent fields omit keys (no `"null"` strings); `has(record.field)`
//!    works because the field simply isn't bound.
//! 3. Enrichment-bound collections are `Value::List<T>`. JSON arrays
//!    are passed through as cel lists; this rule re-asserts itself once
//!    enrichment lands (slice 4).
//! 4. Field access against fields not in the `_kind` schema → evaluation
//!    error, not silent null. cel-interpreter's `get_variable` already
//!    surfaces `UndeclaredReference` for unbound names; we surface that
//!    error verbatim.
//! 5. `now` symbol bound by the SDK per query. Pass `now` to
//!    [`build_context`].
//!
//! v0.1 binds each top-level field of the record as a top-level CEL
//! variable so users write `severity == "high"` rather than
//! `record.severity == "high"`. This matches the recipe shapes in
//! `examples/recipes/`.

use std::sync::Arc;

use cel_interpreter::{Context, Program, Value};
use chrono::{DateTime, FixedOffset, Utc};
use serde_json::Value as JsonValue;

use crate::error::{Result, SidestepError};
use crate::stream::Record;

/// Compile a CEL predicate. Caller-friendly wrapper that maps cel
/// parse errors into [`SidestepError::InvalidParam`].
pub fn compile(expression: &str) -> Result<Program> {
    Program::compile(expression)
        .map_err(|e| SidestepError::InvalidParam("--where".into(), format!("CEL parse error: {e}")))
}

/// Build a CEL context for one record.
///
/// Every domain field is bound *twice*: once as a flat top-level
/// variable so users write `severity == "critical"`, and once as a key
/// on the `record` map so users can use the `has()` macro
/// (`has(record.suppressed_by)`). CEL's `has()` only accepts field
/// access on a map, so the `record` view is the only way to test for
/// absence without triggering the canonical-adapter "missing field is
/// an error" rule (#4).
///
/// `*_at` strings are promoted to `Value::Timestamp` in both views so
/// `created_at < now` and `record.created_at < now` both work.
pub fn build_context(record: &Record, now: DateTime<Utc>) -> Result<Context<'static>> {
    let mut ctx = Context::default();

    // Re-expose `_kind` and `_source` so predicates can reference them.
    // The names match the wire form so users write `_kind == "detection"`.
    ctx.add_variable_from_value("_kind", Value::String(Arc::new(record.kind.clone())));
    ctx.add_variable("_source", &record.source)
        .map_err(|e| SidestepError::InvalidParam("--where".into(), format!("bind _source: {e}")))?;

    // Pre-compute promoted values once and reuse for both bindings.
    let mut record_map: Vec<(String, Value)> = Vec::with_capacity(record.fields.len() + 2);
    record_map.push((
        "_kind".to_string(),
        Value::String(Arc::new(record.kind.clone())),
    ));
    record_map.push((
        "_source".to_string(),
        cel_interpreter::objects::TryIntoValue::try_into_value(&record.source).map_err(|e| {
            SidestepError::InvalidParam("--where".into(), format!("bind record._source: {e}"))
        })?,
    ));

    for (name, value) in &record.fields {
        let promoted = if is_timestamp_field(name) {
            match parse_timestamp(value) {
                Some(ts) => Value::Timestamp(ts),
                None => {
                    cel_interpreter::objects::TryIntoValue::try_into_value(value).map_err(|e| {
                        SidestepError::InvalidParam("--where".into(), format!("bind `{name}`: {e}"))
                    })?
                }
            }
        } else {
            cel_interpreter::objects::TryIntoValue::try_into_value(value).map_err(|e| {
                SidestepError::InvalidParam("--where".into(), format!("bind `{name}`: {e}"))
            })?
        };
        ctx.add_variable_from_value(name.clone(), promoted.clone());
        record_map.push((name.clone(), promoted));
    }

    // Build the `record` map view. Use a HashMap so cel-interpreter
    // converts via its `From<HashMap<K, V>>` impl into a Map value.
    let record_view: std::collections::HashMap<String, Value> = record_map.into_iter().collect();
    ctx.add_variable_from_value("record", Value::from(record_view));

    // The query-time `now` binding.
    ctx.add_variable_from_value("now", Value::Timestamp(to_fixed(now)));

    Ok(ctx)
}

/// Evaluate a compiled predicate against a record. The result must be
/// a CEL boolean — anything else surfaces as an
/// [`SidestepError::InvalidParam`] with the predicate text.
pub fn evaluate(
    program: &Program,
    record: &Record,
    now: DateTime<Utc>,
    predicate_text: &str,
) -> Result<bool> {
    let ctx = build_context(record, now)?;
    let value = program.execute(&ctx).map_err(|e| {
        SidestepError::InvalidParam(
            "--where".into(),
            format!("CEL runtime error in `{predicate_text}`: {e}"),
        )
    })?;
    match value {
        Value::Bool(b) => Ok(b),
        other => Err(SidestepError::InvalidParam(
            "--where".into(),
            format!("CEL predicate must return bool, got {other:?} for `{predicate_text}`"),
        )),
    }
}

/// True when the field name should be promoted to a timestamp by the
/// canonical adapter. Currently: any field ending in `_at`, plus the
/// audit-log `ts` field.
fn is_timestamp_field(name: &str) -> bool {
    name == "ts" || name.ends_with("_at")
}

fn parse_timestamp(v: &JsonValue) -> Option<DateTime<FixedOffset>> {
    let s = v.as_str()?;
    DateTime::parse_from_rfc3339(s).ok()
}

fn to_fixed(t: DateTime<Utc>) -> DateTime<FixedOffset> {
    t.with_timezone(&FixedOffset::east_opt(0).expect("UTC offset is valid"))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::stream::SourceRef;

    fn make_record(kind: &str, body: JsonValue) -> Record {
        Record::wrap(
            kind,
            SourceRef {
                operation_id: "op".into(),
                response_index: 0,
                fetched_at: Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap(),
                trace_ref: None,
            },
            body,
        )
    }

    #[test]
    fn evaluates_a_string_equality() {
        let r = make_record(
            "detection",
            json!({"severity": "critical", "status": "open"}),
        );
        let p = compile("severity == \"critical\"").unwrap();
        assert!(evaluate(&p, &r, Utc::now(), "severity == \"critical\"").unwrap());
    }

    #[test]
    fn supports_in_operator() {
        let r = make_record("detection", json!({"severity": "high", "status": "open"}));
        let p = compile("severity in [\"critical\", \"high\"]").unwrap();
        assert!(evaluate(&p, &r, Utc::now(), "severity in [...]").unwrap());
    }

    #[test]
    fn matches_kind_via_underscore_kind() {
        let r = make_record("rule", json!({"id": "rule_001"}));
        let p = compile("_kind == \"rule\"").unwrap();
        assert!(evaluate(&p, &r, Utc::now(), "_kind == rule").unwrap());
    }

    #[test]
    fn has_returns_false_for_absent_fields_via_record_view() {
        // CEL's `has()` macro only takes field-on-map. Predicates use
        // the `record` namespace for absence checks.
        let r = make_record("rule", json!({"id": "rule_001"}));
        let p = compile("has(record.suppressed_by)").unwrap();
        assert!(!evaluate(&p, &r, Utc::now(), "has(record.suppressed_by)").unwrap());
    }

    #[test]
    fn has_returns_true_for_present_fields_via_record_view() {
        let r = make_record(
            "detection",
            json!({"id": "d1", "suppressed_by": "rule_002"}),
        );
        let p = compile("has(record.suppressed_by)").unwrap();
        assert!(evaluate(&p, &r, Utc::now(), "has(record.suppressed_by)").unwrap());
    }

    #[test]
    fn timestamp_field_promotes_for_comparison_with_now() {
        let r = make_record(
            "detection",
            json!({"id": "d1", "created_at": "2026-04-29T14:23:11Z"}),
        );
        let now = Utc.with_ymd_and_hms(2026, 4, 30, 10, 0, 0).unwrap();
        let p = compile("created_at < now").unwrap();
        assert!(evaluate(&p, &r, now, "created_at < now").unwrap());
    }

    #[test]
    fn nested_field_access_works() {
        let r = make_record(
            "detection",
            json!({"id": "d1", "repo": {"owner": "arcaven", "name": "marvel"}}),
        );
        let p = compile("repo.owner == \"arcaven\"").unwrap();
        assert!(evaluate(&p, &r, Utc::now(), "repo.owner == arcaven").unwrap());
    }

    #[test]
    fn non_bool_result_is_an_error() {
        let r = make_record("detection", json!({"severity": "high"}));
        let p = compile("severity").unwrap();
        let err = evaluate(&p, &r, Utc::now(), "severity").unwrap_err();
        assert!(format!("{err}").contains("must return bool"));
    }

    // Note: cel-interpreter 0.10's antlr4rust parser panics rather than
    // returning Err on some malformed inputs (e.g. `severity ==`). The
    // `compile` wrapper still maps cleanly-rejected parses to
    // SidestepError::InvalidParam — not all malformed inputs are
    // cleanly rejected. Track upstream cel-rust for a fix; until then
    // CLI callers should expect occasional panics on adversarial input.
    #[test]
    fn runtime_error_when_field_not_bound() {
        let r = make_record("rule", json!({"id": "rule_001"}));
        let p = compile("totally_made_up_field == \"x\"").unwrap();
        let err = evaluate(&p, &r, Utc::now(), "totally_made_up_field == ...").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("CEL runtime error"), "got: {msg}");
    }

    #[test]
    fn boolean_combinator_works() {
        let r = make_record(
            "detection",
            json!({"severity": "high", "status": "open", "created_at": "2026-04-30T08:00:00Z"}),
        );
        let p = compile("(severity == \"critical\" || severity == \"high\") && status == \"open\"")
            .unwrap();
        assert!(evaluate(&p, &r, Utc::now(), "...").unwrap());
    }
}
