//! `diff`: set difference over two record streams, keyed on a tuple of
//! fields.
//!
//! The current stream is compared with a prior one. A record's identity
//! is the tuple of values at the `on` paths, so two records with the same
//! tuple are the same member of the set, whatever else differs. Each
//! output record is a copy of its source with a `_diff` label:
//!
//! * `added`: the key is in the current stream and not in the prior one;
//! * `removed`: the key is in the prior stream and not in the current one;
//! * `unchanged`: the key is in both (the current record is emitted).
//!
//! Rules:
//!
//! * A record missing a key field (or holding `null`) has no identity and
//!   fails the diff, naming the field. A silent skip would read as "not
//!   changed" when the truth is "not comparable".
//! * Duplicate keys within one stream collapse to the first record; the
//!   number collapsed is reported so a miner can see it.
//! * Output order is the current stream's order for `added` and
//!   `unchanged`, then the prior stream's order for `removed`.
//! * An existing `_diff` field on an input record is overwritten.
//!
//! No network, no clock: the same two inputs give the same output.

use std::collections::HashSet;

use serde_json::Value;

use crate::rank::lookup;
use crate::stream::Record;

/// Which labelled records to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Semantics {
    Added,
    Removed,
    Both,
}

impl Semantics {
    pub fn as_str(self) -> &'static str {
        match self {
            Semantics::Added => "added",
            Semantics::Removed => "removed",
            Semantics::Both => "both",
        }
    }
}

/// Result of a diff: the records to emit, and the counts over the whole
/// comparison (not only what was emitted).
#[derive(Debug)]
pub struct DiffResult {
    pub records: Vec<Record>,
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub duplicate_current: usize,
    pub duplicate_prior: usize,
}

/// Check the `--on` paths: at least one, each made of non-empty names
/// joined by dots.
pub fn validate_on(on: &[String]) -> Result<(), String> {
    if on.is_empty() {
        return Err("--on needs at least one field".to_string());
    }
    for path in on {
        if path.is_empty() || path.split('.').any(str::is_empty) {
            return Err(format!(
                "--on {path:?}: a key field must be non-empty names joined by dots"
            ));
        }
    }
    Ok(())
}

/// The identity of `record` under `on`, or an error naming the first
/// path it lacks. `side` and `index` (1-based) say where it came from.
fn key_of(record: &Record, on: &[String], side: &str, index: usize) -> Result<String, String> {
    let mut parts = Vec::with_capacity(on.len());
    for path in on {
        match lookup(record, path) {
            Some(v) => parts.push(v),
            None => {
                return Err(format!(
                    "{side} record {index} has no value at key field {path:?}"
                ));
            }
        }
    }
    Ok(Value::Array(parts).to_string())
}

fn label(mut record: Record, label: &str) -> Record {
    record
        .fields
        .insert("_diff".to_string(), Value::String(label.to_string()));
    record
}

/// Compute the diff. `current` is the stream under inspection, `prior`
/// the baseline it is compared with.
pub fn diff(
    current: Vec<Record>,
    prior: Vec<Record>,
    on: &[String],
    semantics: Semantics,
    include_unchanged: bool,
) -> Result<DiffResult, String> {
    // Keys first, so a record that cannot be compared fails the run
    // before anything is decided.
    let mut prior_keyed: Vec<(String, Record)> = Vec::new();
    let mut prior_seen: HashSet<String> = HashSet::new();
    let mut duplicate_prior = 0usize;
    for (i, r) in prior.into_iter().enumerate() {
        let k = key_of(&r, on, "prior", i + 1)?;
        if prior_seen.insert(k.clone()) {
            prior_keyed.push((k, r));
        } else {
            duplicate_prior += 1;
        }
    }
    let mut current_keyed: Vec<(String, Record)> = Vec::new();
    let mut current_seen: HashSet<String> = HashSet::new();
    let mut duplicate_current = 0usize;
    for (i, r) in current.into_iter().enumerate() {
        let k = key_of(&r, on, "current", i + 1)?;
        if current_seen.insert(k.clone()) {
            current_keyed.push((k, r));
        } else {
            duplicate_current += 1;
        }
    }

    let want_added = matches!(semantics, Semantics::Added | Semantics::Both);
    let want_removed = matches!(semantics, Semantics::Removed | Semantics::Both);

    let mut records = Vec::new();
    let (mut added, mut removed, mut unchanged) = (0usize, 0usize, 0usize);
    for (k, r) in current_keyed {
        if prior_seen.contains(&k) {
            unchanged += 1;
            if include_unchanged {
                records.push(label(r, "unchanged"));
            }
        } else {
            added += 1;
            if want_added {
                records.push(label(r, "added"));
            }
        }
    }
    for (k, r) in prior_keyed {
        if !current_seen.contains(&k) {
            removed += 1;
            if want_removed {
                records.push(label(r, "removed"));
            }
        }
    }

    Ok(DiffResult {
        records,
        added,
        removed,
        unchanged,
        duplicate_current,
        duplicate_prior,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::stream::SourceRef;

    fn record(fields: Value) -> Record {
        let Value::Object(map) = fields else {
            panic!("object")
        };
        Record {
            kind: "detection".into(),
            source: SourceRef::now("op", 0),
            fields: map,
        }
    }

    fn on(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|s| s.to_string()).collect()
    }

    fn pairs(result: &DiffResult) -> Vec<(String, String)> {
        result
            .records
            .iter()
            .map(|r| {
                (
                    r.get("id").unwrap().as_str().unwrap().to_string(),
                    r.get("_diff").unwrap().as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn partitions_into_added_removed_unchanged() {
        let current = vec![record(json!({"id": "a"})), record(json!({"id": "b"}))];
        let prior = vec![record(json!({"id": "b"})), record(json!({"id": "c"}))];
        let r = diff(current, prior, &on(&["id"]), Semantics::Both, true).unwrap();
        assert_eq!((r.added, r.removed, r.unchanged), (1, 1, 1));
        assert_eq!(
            pairs(&r),
            [
                ("a".to_string(), "added".to_string()),
                ("b".to_string(), "unchanged".to_string()),
                ("c".to_string(), "removed".to_string())
            ]
        );
    }

    #[test]
    fn counts_cover_the_whole_comparison_not_only_what_is_emitted() {
        let current = vec![record(json!({"id": "a"})), record(json!({"id": "b"}))];
        let prior = vec![record(json!({"id": "b"})), record(json!({"id": "c"}))];
        let r = diff(current, prior, &on(&["id"]), Semantics::Added, false).unwrap();
        assert_eq!((r.added, r.removed, r.unchanged), (1, 1, 1));
        assert_eq!(r.records.len(), 1);
    }

    #[test]
    fn key_values_are_typed() {
        // 1 (number) and "1" (string) are different members.
        let current = vec![record(json!({"id": 1}))];
        let prior = vec![record(json!({"id": "1"}))];
        let r = diff(current, prior, &on(&["id"]), Semantics::Both, false).unwrap();
        assert_eq!((r.added, r.removed, r.unchanged), (1, 1, 0));
    }

    #[test]
    fn tuple_order_matters_only_through_the_declared_paths() {
        let a = record(json!({"x": 1, "y": 2}));
        let b = record(json!({"x": 2, "y": 1}));
        let r = diff(vec![a], vec![b], &on(&["x", "y"]), Semantics::Both, false).unwrap();
        assert_eq!((r.added, r.removed), (1, 1));
    }

    #[test]
    fn duplicates_collapse_and_are_counted() {
        let current = vec![
            record(json!({"id": "a", "n": 1})),
            record(json!({"id": "a", "n": 2})),
        ];
        let prior = vec![
            record(json!({"id": "z"})),
            record(json!({"id": "z"})),
            record(json!({"id": "z"})),
        ];
        let r = diff(current, prior, &on(&["id"]), Semantics::Both, false).unwrap();
        assert_eq!((r.duplicate_current, r.duplicate_prior), (1, 2));
        assert_eq!(r.records[0].get("n").unwrap(), 1);
    }

    #[test]
    fn a_missing_or_null_key_field_is_an_error_naming_side_and_field() {
        let err = diff(
            vec![record(json!({"id": "a"})), record(json!({"id": null}))],
            vec![],
            &on(&["id"]),
            Semantics::Both,
            false,
        )
        .unwrap_err();
        assert!(err.contains("current record 2"), "{err}");
        assert!(err.contains("\"id\""), "{err}");
        let err = diff(
            vec![],
            vec![record(json!({"other": 1}))],
            &on(&["id"]),
            Semantics::Both,
            false,
        )
        .unwrap_err();
        assert!(err.contains("prior record 1"), "{err}");
    }

    #[test]
    fn an_existing_diff_field_is_overwritten() {
        let r = diff(
            vec![record(json!({"id": "a", "_diff": "stale"}))],
            vec![],
            &on(&["id"]),
            Semantics::Both,
            false,
        )
        .unwrap();
        assert_eq!(r.records[0].get("_diff").unwrap(), "added");
    }
}
