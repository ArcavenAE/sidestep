//! `rank`: deterministic ordering of a record stream by typed fields.
//!
//! The same input and the same keys always give the same output. No
//! network, no clock, no randomness: ties keep input order (the sort is
//! stable), so a ranking an agent expressed can be replayed and diffed.
//!
//! Ordering rules, per key:
//!
//! * A key is a dotted field path (`repo.name`) and a direction. The
//!   default direction is descending, highest first, because a ranking
//!   is read from the top.
//! * A record whose path is missing or `null` goes last in both
//!   directions, so a gap in the data never outranks real values.
//! * Numbers compare as numbers, booleans as `false < true`, strings
//!   bytewise. The field named `severity` uses severity order
//!   (`critical > high > medium > low > info`) when both values are
//!   strings, and a value outside that set ranks below every known one.
//! * Values of different types order by type: number, bool, string,
//!   then arrays and objects (compared by their JSON text).

use std::cmp::Ordering;

use serde_json::Value;

use crate::enrich::severity_rank;
use crate::stream::Record;

/// Sort direction of one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Asc,
    Desc,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Asc => "asc",
            Direction::Desc => "desc",
        }
    }
}

/// One `--by` key: a field path and a direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortKey {
    pub path: String,
    pub direction: Direction,
}

impl SortKey {
    /// Parse `FIELD`, `FIELD:asc` or `FIELD:desc`. A bare field is
    /// descending.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (path, direction) = match spec.rsplit_once(':') {
            None => (spec, Direction::Desc),
            Some((path, "asc")) => (path, Direction::Asc),
            Some((path, "desc")) => (path, Direction::Desc),
            Some((_, other)) => {
                return Err(format!(
                    "--by {spec:?}: unknown direction {other:?}; expected asc or desc"
                ));
            }
        };
        if path.is_empty() || path.split('.').any(str::is_empty) {
            return Err(format!(
                "--by {spec:?}: the field path must be non-empty names joined by dots"
            ));
        }
        Ok(Self {
            path: path.to_string(),
            direction,
        })
    }
}

/// Look up a dotted path. `_kind` reads the record's kind; any other
/// first segment reads a domain field. A missing step or a `null`
/// yields `None`.
fn lookup(record: &Record, path: &str) -> Option<Value> {
    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut current = if first == "_kind" {
        Value::String(record.kind.clone())
    } else {
        record.get(first)?.clone()
    };
    for seg in segments {
        current = current.get(seg)?.clone();
    }
    if current.is_null() {
        None
    } else {
        Some(current)
    }
}

fn type_rank(v: &Value) -> u8 {
    match v {
        Value::Number(_) => 0,
        Value::Bool(_) => 1,
        Value::String(_) => 2,
        _ => 3,
    }
}

/// Order two present values, ascending.
fn compare_present(path: &str, a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (x.as_f64().unwrap_or(0.0), y.as_f64().unwrap_or(0.0));
            x.partial_cmp(&y).unwrap_or(Ordering::Equal)
        }
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::String(x), Value::String(y)) => {
            if path.rsplit('.').next() == Some("severity") {
                // Known severities by rank; unknown below every known.
                let (rx, ry) = (severity_rank(x), severity_rank(y));
                match (rx, ry) {
                    (Some(rx), Some(ry)) => return rx.cmp(&ry),
                    (Some(_), None) => return Ordering::Greater,
                    (None, Some(_)) => return Ordering::Less,
                    (None, None) => {}
                }
            }
            x.as_bytes().cmp(y.as_bytes())
        }
        _ => {
            let (ra, rb) = (type_rank(a), type_rank(b));
            if ra != rb {
                ra.cmp(&rb)
            } else {
                a.to_string().cmp(&b.to_string())
            }
        }
    }
}

fn compare_records(keys: &[SortKey], a: &Record, b: &Record) -> Ordering {
    for key in keys {
        let (va, vb) = (lookup(a, &key.path), lookup(b, &key.path));
        let ord = match (va, vb) {
            (None, None) => Ordering::Equal,
            // Absent goes last whatever the direction.
            (None, Some(_)) => return Ordering::Greater,
            (Some(_), None) => return Ordering::Less,
            (Some(x), Some(y)) => {
                let o = compare_present(&key.path, &x, &y);
                match key.direction {
                    Direction::Asc => o,
                    Direction::Desc => o.reverse(),
                }
            }
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// How many records had no usable value at each key's path.
pub fn absent_counts(records: &[Record], keys: &[SortKey]) -> Vec<usize> {
    keys.iter()
        .map(|k| {
            records
                .iter()
                .filter(|r| lookup(r, &k.path).is_none())
                .count()
        })
        .collect()
}

/// Rank `records` by `keys` (earlier keys win) and keep the first
/// `top` when given. Stable: ties keep input order.
pub fn rank(mut records: Vec<Record>, keys: &[SortKey], top: Option<usize>) -> Vec<Record> {
    records.sort_by(|a, b| compare_records(keys, a, b));
    if let Some(n) = top {
        records.truncate(n);
    }
    records
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

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

    fn ids(records: &[Record]) -> Vec<&str> {
        records
            .iter()
            .map(|r| r.get("id").and_then(Value::as_str).unwrap())
            .collect()
    }

    #[test]
    fn parse_accepts_bare_asc_and_desc() {
        assert_eq!(
            SortKey::parse("severity").unwrap(),
            SortKey {
                path: "severity".into(),
                direction: Direction::Desc
            }
        );
        assert_eq!(
            SortKey::parse("repo.name:asc").unwrap(),
            SortKey {
                path: "repo.name".into(),
                direction: Direction::Asc
            }
        );
    }

    #[test]
    fn parse_refuses_bad_directions_and_paths() {
        assert!(SortKey::parse("severity:up").unwrap_err().contains("up"));
        assert!(SortKey::parse("").is_err());
        assert!(SortKey::parse(":asc").is_err());
        assert!(SortKey::parse("a..b").is_err());
        assert!(SortKey::parse("a.:desc").is_err());
    }

    #[test]
    fn rank_is_deterministic_and_stable() {
        let input = vec![
            record(json!({"id": "a", "n": 1})),
            record(json!({"id": "b", "n": 2})),
            record(json!({"id": "c", "n": 1})),
            record(json!({"id": "d", "n": 2})),
        ];
        let keys = [SortKey::parse("n").unwrap()];
        let first = rank(input.clone(), &keys, None);
        let second = rank(input, &keys, None);
        assert_eq!(ids(&first), ["b", "d", "a", "c"]);
        assert_eq!(ids(&first), ids(&second));
    }

    #[test]
    fn mixed_types_order_by_type_then_value() {
        let input = vec![
            record(json!({"id": "s", "v": "x"})),
            record(json!({"id": "n", "v": 5})),
            record(json!({"id": "b", "v": true})),
        ];
        let out = rank(input, &[SortKey::parse("v:asc").unwrap()], None);
        assert_eq!(ids(&out), ["n", "b", "s"]);
    }

    #[test]
    fn kind_is_addressable() {
        let mut other = record(json!({"id": "x"}));
        other.kind = "alpha".into();
        let input = vec![record(json!({"id": "y"})), other];
        let out = rank(input, &[SortKey::parse("_kind:asc").unwrap()], None);
        assert_eq!(ids(&out), ["x", "y"]);
    }

    #[test]
    fn absent_counts_reports_gaps_per_key() {
        let input = vec![
            record(json!({"id": "a", "severity": "low"})),
            record(json!({"id": "b", "severity": null})),
            record(json!({"id": "c"})),
        ];
        let keys = [
            SortKey::parse("severity").unwrap(),
            SortKey::parse("id").unwrap(),
        ];
        assert_eq!(absent_counts(&input, &keys), vec![2, 0]);
    }

    #[test]
    fn a_non_object_body_is_wrapped_and_rankable() {
        let r = Record::wrap("x", SourceRef::now("op", 0), json!(7));
        assert_eq!(r.fields, {
            let mut m = Map::new();
            m.insert("value".into(), json!(7));
            m
        });
        assert!(lookup(&r, "value").is_some());
    }
}
