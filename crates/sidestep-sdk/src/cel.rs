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

/// Run `f` with panics caught and the default panic hook suppressed
/// for this thread. cel-interpreter 0.10's antlr4rust parser panics
/// (rather than returning `Err`) on some malformed predicates, e.g.
/// `severity ==` with a missing operand (aae-orc-qvk9). Without this
/// guard a user typo aborts the CLI with a backtrace. The hook is
/// installed once per process and consults a thread-local flag, so
/// concurrent callers (tests) don't race on global hook swaps.
fn with_panic_suppressed<T>(
    f: impl FnOnce() -> T + std::panic::UnwindSafe,
) -> std::thread::Result<T> {
    use std::cell::Cell;
    use std::sync::Once;
    thread_local! {
        static SUPPRESS: Cell<bool> = const { Cell::new(false) };
    }
    static HOOK_INIT: Once = Once::new();
    HOOK_INIT.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !SUPPRESS.with(|s| s.get()) {
                prev(info);
            }
        }));
    });
    SUPPRESS.with(|s| s.set(true));
    let result = std::panic::catch_unwind(f);
    SUPPRESS.with(|s| s.set(false));
    result
}

/// Compile a CEL predicate. Caller-friendly wrapper that maps cel
/// parse errors into [`SidestepError::InvalidParam`] — including
/// upstream parser panics, which are caught and surfaced as the same
/// error shape (aae-orc-qvk9).
pub fn compile(expression: &str) -> Result<Program> {
    match with_panic_suppressed(|| Program::compile(expression)) {
        Ok(parsed) => parsed.map_err(|e| {
            SidestepError::InvalidParam("--where".into(), format!("CEL parse error: {e}"))
        }),
        Err(_) => Err(SidestepError::InvalidParam(
            "--where".into(),
            format!(
                "CEL parse error: malformed predicate `{expression}` \
                 (the upstream cel parser could not recover — check for \
                 incomplete operands, e.g. a trailing `==`)"
            ),
        )),
    }
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
    let executed = with_panic_suppressed(std::panic::AssertUnwindSafe(|| program.execute(&ctx)))
        .map_err(|_| {
            SidestepError::InvalidParam(
                "--where".into(),
                format!(
                    "CEL runtime panic in `{predicate_text}` (upstream cel bug — aae-orc-qvk9)"
                ),
            )
        })?;
    let value = executed.map_err(|e| {
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

/// Mining-oriented static analysis of a predicate (aae-orc-deux).
///
/// The audit v2 schema (finding-001) reserves two fields that complete
/// Murat's sugar-design dataset: `field_paths_referenced` (which
/// record fields a predicate touches) and `literal_values_by_path`
/// (which constants it compares them against). `predicate_ast_shape`
/// clusters structurally-identical predicates; these two say what the
/// cluster is *about*.
///
/// The predicate text is re-parsed with `cel-parser` (the same parser
/// generation cel-interpreter embeds) because `Program`'s AST is
/// private. Parse failures — including upstream panics — yield `None`
/// and the audit fields are simply omitted; mining fields must never
/// fail an invocation that the execution path accepted.
#[derive(Debug, Default, PartialEq)]
pub struct PredicateRefs {
    /// Sorted, deduped dotted field paths. `record.`-prefixed access
    /// is folded onto the bare path so `severity` and
    /// `record.severity` cluster together; the `now` binding and
    /// comprehension internals (`__result__`, iteration variables)
    /// are excluded.
    pub field_paths: Vec<String>,
    /// Path → sorted literal values it is compared against, collected
    /// from calls in which the path and the literal are sibling
    /// arguments (`severity == "critical"`, `severity in ["a", "b"]`).
    pub literals_by_path: std::collections::BTreeMap<String, Vec<String>>,
}

pub fn analyze_predicate(expression: &str) -> Option<PredicateRefs> {
    use std::collections::{BTreeMap, BTreeSet};
    let parsed = with_panic_suppressed(|| cel_parser::Parser::new().parse(expression))
        .ok()?
        .ok()?;
    let mut paths: BTreeSet<String> = BTreeSet::new();
    let mut lits: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut internals: BTreeSet<String> = BTreeSet::new();
    walk_expr(&parsed, &mut paths, &mut lits, &mut internals);
    let is_internal = |p: &String| {
        internals
            .iter()
            .any(|v| p == v || p.starts_with(&format!("{v}.")))
    };
    Some(PredicateRefs {
        field_paths: paths.iter().filter(|p| !is_internal(p)).cloned().collect(),
        literals_by_path: lits
            .into_iter()
            .filter(|(p, _)| !is_internal(p))
            .map(|(p, vs)| (p, vs.into_iter().collect()))
            .collect(),
    })
}

/// Render a maximal `Ident`/`Select` chain as a dotted path, or `None`
/// when the expression is not a plain field access.
fn path_of(e: &cel_parser::Expression) -> Option<String> {
    use cel_parser::ast::Expr;
    match &e.expr {
        Expr::Ident(name) => Some(name.clone()),
        Expr::Select(sel) => path_of(&sel.operand).map(|p| format!("{p}.{}", sel.field)),
        _ => None,
    }
}

/// Fold the `record.` view onto bare paths and drop non-field bindings.
fn normalize_path(path: String) -> Option<String> {
    let path = match path.strip_prefix("record.") {
        Some(rest) => rest.to_string(),
        None => path,
    };
    if path == "now" || path == "record" || path.starts_with("__") {
        None
    } else {
        Some(path)
    }
}

fn literal_repr(v: &cel_parser::reference::Val) -> String {
    use cel_parser::reference::Val;
    match v {
        Val::String(s) => s.clone(),
        Val::Boolean(b) => b.to_string(),
        Val::Int(i) => i.to_string(),
        Val::UInt(u) => u.to_string(),
        Val::Double(d) => d.to_string(),
        Val::Bytes(_) => "<bytes>".to_string(),
        Val::Null => "null".to_string(),
    }
}

fn walk_expr(
    e: &cel_parser::Expression,
    paths: &mut std::collections::BTreeSet<String>,
    lits: &mut std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    internals: &mut std::collections::BTreeSet<String>,
) {
    use cel_parser::ast::{EntryExpr, Expr};
    match &e.expr {
        Expr::Ident(_) | Expr::Select(_) => {
            if let Some(p) = path_of(e).and_then(normalize_path) {
                paths.insert(p);
            } else if let Expr::Select(sel) = &e.expr {
                // Selection off a non-path operand (call result, list
                // index, …) — the operand still references fields.
                walk_expr(&sel.operand, paths, lits, internals);
            }
        }
        Expr::Call(call) => {
            let sub: Vec<&cel_parser::Expression> = call
                .target
                .iter()
                .map(|b| b.as_ref())
                .chain(call.args.iter())
                .collect();
            // Pair sibling path/literal arguments: `severity == "high"`,
            // `severity in ["a", "b"]`. Literals with no sibling path
            // (`duration("24h")`) map to nothing.
            let call_paths: Vec<String> = sub
                .iter()
                .filter_map(|a| path_of(a).and_then(normalize_path))
                .collect();
            let mut call_lits: Vec<String> = Vec::new();
            for a in &sub {
                match &a.expr {
                    Expr::Literal(v) => call_lits.push(literal_repr(v)),
                    Expr::List(list) => {
                        for el in &list.elements {
                            if let Expr::Literal(v) = &el.expr {
                                call_lits.push(literal_repr(v));
                            }
                        }
                    }
                    _ => {}
                }
            }
            for p in &call_paths {
                for l in &call_lits {
                    lits.entry(p.clone()).or_default().insert(l.clone());
                }
            }
            for a in sub {
                walk_expr(a, paths, lits, internals);
            }
        }
        Expr::Comprehension(c) => {
            // Macro-generated internals (`exists`, `all`, `has` on
            // maps): the iteration/accumulator variables are not
            // record fields.
            internals.insert(c.iter_var.clone());
            if let Some(v2) = &c.iter_var2 {
                internals.insert(v2.clone());
            }
            internals.insert(c.accu_var.clone());
            for sub in [
                &c.iter_range,
                &c.accu_init,
                &c.loop_cond,
                &c.loop_step,
                &c.result,
            ] {
                walk_expr(sub, paths, lits, internals);
            }
        }
        Expr::List(l) => {
            for el in &l.elements {
                walk_expr(el, paths, lits, internals);
            }
        }
        Expr::Map(m) => {
            for entry in &m.entries {
                match &entry.expr {
                    EntryExpr::MapEntry(me) => {
                        walk_expr(&me.key, paths, lits, internals);
                        walk_expr(&me.value, paths, lits, internals);
                    }
                    EntryExpr::StructField(sf) => walk_expr(&sf.value, paths, lits, internals),
                }
            }
        }
        Expr::Struct(s) => {
            for entry in &s.entries {
                match &entry.expr {
                    EntryExpr::MapEntry(me) => {
                        walk_expr(&me.key, paths, lits, internals);
                        walk_expr(&me.value, paths, lits, internals);
                    }
                    EntryExpr::StructField(sf) => walk_expr(&sf.value, paths, lits, internals),
                }
            }
        }
        Expr::Literal(_) | Expr::Unspecified => {}
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
    fn analyze_simple_equality() {
        let refs = analyze_predicate(r#"severity == "critical""#).unwrap();
        assert_eq!(refs.field_paths, vec!["severity"]);
        assert_eq!(
            refs.literals_by_path.get("severity").unwrap(),
            &vec!["critical".to_string()]
        );
    }

    #[test]
    fn analyze_in_list_and_conjunction() {
        let refs =
            analyze_predicate(r#"severity in ["critical", "high"] && status == "open""#).unwrap();
        assert_eq!(refs.field_paths, vec!["severity", "status"]);
        assert_eq!(
            refs.literals_by_path.get("severity").unwrap(),
            &vec!["critical".to_string(), "high".to_string()]
        );
        assert_eq!(
            refs.literals_by_path.get("status").unwrap(),
            &vec!["open".to_string()]
        );
    }

    #[test]
    fn analyze_folds_record_prefix_and_skips_now() {
        // record.severity and severity must cluster as one path; the
        // `now` binding and duration literal map to nothing.
        let refs =
            analyze_predicate(r#"record.severity == "high" && created_at > now - duration("24h")"#)
                .unwrap();
        assert_eq!(refs.field_paths, vec!["created_at", "severity"]);
        assert!(!refs.literals_by_path.contains_key("now"));
        assert!(!refs.literals_by_path.contains_key("created_at"));
    }

    #[test]
    fn analyze_has_macro_references_the_field() {
        let refs = analyze_predicate("has(record.suppressed_by)").unwrap();
        assert_eq!(refs.field_paths, vec!["suppressed_by"]);
    }

    #[test]
    fn analyze_nested_path_and_numeric_literal() {
        let refs = analyze_predicate(r#"repo.owner == "acme-corp" && count > 3"#).unwrap();
        assert_eq!(refs.field_paths, vec!["count", "repo.owner"]);
        assert_eq!(
            refs.literals_by_path.get("count").unwrap(),
            &vec!["3".to_string()]
        );
    }

    #[test]
    fn analyze_comprehension_excludes_iteration_vars() {
        let refs = analyze_predicate(r#"labels.exists(l, l == "urgent")"#).unwrap();
        assert!(refs.field_paths.contains(&"labels".to_string()));
        assert!(!refs.field_paths.contains(&"l".to_string()));
        assert!(!refs.field_paths.iter().any(|p| p.starts_with("__")));
    }

    #[test]
    fn analyze_malformed_predicate_is_none() {
        assert!(analyze_predicate("severity ==").is_none());
    }

    #[test]
    fn compile_survives_upstream_parser_panic() {
        // `severity ==` (missing right operand) makes cel-interpreter
        // 0.10's antlr4rust parser panic instead of returning Err
        // (aae-orc-qvk9). The guard must convert it into the same
        // InvalidParam a clean parse error produces.
        let err = compile("severity ==").expect_err("must be Err, not a panic");
        let msg = format!("{err}");
        assert!(msg.contains("CEL parse error"), "got: {msg}");
    }

    #[test]
    fn compile_still_reports_clean_parse_errors() {
        let err = compile("severity === \"x\"").expect_err("invalid CEL");
        assert!(format!("{err}").contains("CEL parse error"));
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
