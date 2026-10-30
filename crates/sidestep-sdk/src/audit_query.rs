//! `audit query`: mine the local audit trail.
//!
//! The reader behind the pattern-mining passes that were first done with a
//! throwaway script: a corpus summary, counts grouped by a field, and pairs
//! of values that occur close together in time. It reads the trail only; it
//! never touches the network, and the trail holds no payloads, so what it
//! counts is what was called and how it ended.
//!
//! Rules:
//!
//! * Spans are ordered by `ts_start`; spans with the same time keep file and
//!   line order. A span whose `ts_start` is missing or not RFC 3339 cannot be
//!   placed in time, so it is left out and counted in `spans_without_time`.
//!   Lines that are not JSON objects are counted in `lines_unparsed`.
//! * A field is a dotted path into the span (`operation.id`, `response.status`)
//!   or the pseudo-field `_day`, the UTC date of `ts_start`. A span without the
//!   field (or with `null`) groups under `<none>`. Numbers and booleans group
//!   by their text; arrays and objects by their JSON text.
//! * Groups come out highest count first, ties by key. Pairs come out the same
//!   way, ties by `a` then `b`.
//! * Co-occurrence follows the prototype: for each span, every later span within
//!   the window whose value differs counts one unordered pair. Spans with no value
//!   for the field are skipped. The window is inclusive.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde_json::{Map, Value, json};

use crate::replay::SOURCE_AUDIT_TRAIL;
use crate::stream::{Record, SourceRef};

/// `_kind` of the corpus summary.
pub const KIND_CORPUS: &str = "audit_corpus";
/// `_kind` of one group count.
pub const KIND_GROUP: &str = "audit_group";
/// `_kind` of one co-occurring pair.
pub const KIND_PAIR: &str = "audit_pair";

/// The field name a span lacking the field groups under.
pub const NONE_KEY: &str = "<none>";

/// One span that has a usable time.
#[derive(Debug)]
pub struct TrailSpan {
    pub ts: DateTime<Utc>,
    pub ts_text: String,
    pub fields: Map<String, Value>,
}

/// What a read of the whole trail found.
#[derive(Debug)]
pub struct Trail {
    pub spans: Vec<TrailSpan>,
    pub files_read: usize,
    pub lines_unparsed: usize,
    pub spans_without_time: usize,
}

/// Read every `*.jsonl` file in `dir`.
pub fn read_trail(dir: &Path) -> Result<Trail, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("read audit trail directory {}: {e}", dir.display()))?;
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("jsonl"))
        .collect();
    files.sort();

    let mut found: Vec<(DateTime<Utc>, usize, usize, TrailSpan)> = Vec::new();
    let mut lines_unparsed = 0usize;
    let mut spans_without_time = 0usize;
    for (fi, path) in files.iter().enumerate() {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("read audit trail file {}: {e}", path.display()))?;
        let text = String::from_utf8_lossy(&bytes);
        for (li, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(line) else {
                lines_unparsed += 1;
                continue;
            };
            let ts_text = fields
                .get("ts_start")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let Ok(ts) = DateTime::parse_from_rfc3339(&ts_text) else {
                spans_without_time += 1;
                continue;
            };
            let ts = ts.with_timezone(&Utc);
            found.push((
                ts,
                fi,
                li,
                TrailSpan {
                    ts,
                    ts_text,
                    fields,
                },
            ));
        }
    }
    found.sort_by_key(|a| (a.0, a.1, a.2));
    Ok(Trail {
        spans: found.into_iter().map(|(_, _, _, s)| s).collect(),
        files_read: files.len(),
        lines_unparsed,
        spans_without_time,
    })
}

/// A span-count unit: seconds, minutes, hours, days or weeks.
fn parse_span(s: &str) -> Option<Duration> {
    let unit = s.chars().last()?;
    let digits = &s[..s.len() - unit.len_utf8()];
    if digits.is_empty() || digits.len() > 7 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    if n == 0 {
        return None;
    }
    match unit {
        's' => Duration::try_seconds(n),
        'm' => Duration::try_minutes(n),
        'h' => Duration::try_hours(n),
        'd' => Duration::try_days(n),
        'w' => Duration::try_weeks(n),
        _ => None,
    }
}

/// Parse a `--since` value: `30m`, `12h`, `7d`, `2w` (back from `now`), an
/// RFC 3339 timestamp, or a `YYYY-MM-DD` date (that UTC midnight).
pub fn parse_since(s: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    if let Some(d) = parse_span(s) {
        return Ok(now - d);
    }
    if let Ok(ts) = DateTime::parse_from_rfc3339(s) {
        return Ok(ts.with_timezone(&Utc));
    }
    if let Ok(day) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(day.and_hms_opt(0, 0, 0).expect("midnight").and_utc());
    }
    Err(format!(
        "--since {s:?}: expected a duration (30m, 12h, 7d, 2w), an RFC 3339 timestamp or a YYYY-MM-DD date"
    ))
}

/// Parse a `--cooccur` window: a duration such as `60s` or `5m`.
pub fn parse_window(s: &str) -> Result<Duration, String> {
    parse_span(s).ok_or_else(|| {
        format!("--cooccur {s:?}: expected a duration above zero (60s, 5m, 1h, 1d, 1w)")
    })
}

/// Check a `--group-by` path: non-empty names joined by dots.
pub fn validate_field(path: &str) -> Result<(), String> {
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(format!(
            "--group-by {path:?}: a field must be non-empty names joined by dots"
        ));
    }
    Ok(())
}

/// The spans at or after `since` (all of them when `None`).
pub fn select(trail: &Trail, since: Option<DateTime<Utc>>) -> Vec<&TrailSpan> {
    trail
        .spans
        .iter()
        .filter(|s| since.is_none_or(|t| s.ts >= t))
        .collect()
}

/// The text of `path` in `span`, or `None` when absent or `null`.
fn field_text(span: &TrailSpan, path: &str) -> Option<String> {
    if path == "_day" {
        return Some(span.ts.format("%Y-%m-%d").to_string());
    }
    let mut segments = path.split('.');
    let mut current = span.fields.get(segments.next()?)?;
    for seg in segments {
        current = current.get(seg)?;
    }
    match current {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn source_at(spans: &[&TrailSpan], index: usize) -> SourceRef {
    SourceRef {
        operation_id: SOURCE_AUDIT_TRAIL.to_string(),
        response_index: index,
        fetched_at: spans.last().map_or_else(Utc::now, |s| s.ts),
        trace_ref: None,
    }
}

fn record(kind: &str, source: SourceRef, fields: Value) -> Record {
    let Value::Object(fields) = fields else {
        unreachable!("record fields are built as objects")
    };
    Record {
        kind: kind.to_string(),
        source,
        fields,
    }
}

/// The corpus summary of the selected spans.
pub fn corpus(spans: &[&TrailSpan], trail: &Trail) -> Record {
    let days: BTreeSet<_> = spans.iter().map(|s| s.ts.date_naive()).collect();
    let first = spans.first().map(|s| s.ts_text.clone());
    let last = spans.last().map(|s| s.ts_text.clone());
    record(
        KIND_CORPUS,
        source_at(spans, 0),
        json!({
            "records": spans.len(),
            "active_days": days.len(),
            "first_ts": first,
            "last_ts": last,
            "files_read": trail.files_read,
            "lines_unparsed": trail.lines_unparsed,
            "spans_without_time": trail.spans_without_time,
        }),
    )
}

/// Count the selected spans by the value of `field`.
pub fn group_by(spans: &[&TrailSpan], field: &str, top: Option<usize>) -> Vec<Record> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for s in spans {
        let key = field_text(s, field).unwrap_or_else(|| NONE_KEY.to_string());
        *counts.entry(key).or_default() += 1;
    }
    let mut rows: Vec<(String, usize)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if let Some(n) = top {
        rows.truncate(n);
    }
    rows.into_iter()
        .enumerate()
        .map(|(i, (key, count))| {
            record(
                KIND_GROUP,
                source_at(spans, i),
                json!({"field": field, "key": key, "count": count}),
            )
        })
        .collect()
}

/// Count unordered pairs of distinct `field` values that occur within
/// `window` of each other.
pub fn cooccur(
    spans: &[&TrailSpan],
    field: &str,
    window: Duration,
    top: Option<usize>,
) -> Vec<Record> {
    let keyed: Vec<(DateTime<Utc>, String)> = spans
        .iter()
        .filter_map(|s| field_text(s, field).map(|k| (s.ts, k)))
        .collect();
    let mut pairs: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (i, (ts_a, a)) in keyed.iter().enumerate() {
        for (ts_b, b) in &keyed[i + 1..] {
            if *ts_b - *ts_a > window {
                break;
            }
            if a == b {
                continue;
            }
            let pair = if a < b {
                (a.clone(), b.clone())
            } else {
                (b.clone(), a.clone())
            };
            *pairs.entry(pair).or_default() += 1;
        }
    }
    let mut rows: Vec<((String, String), usize)> = pairs.into_iter().collect();
    rows.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    if let Some(n) = top {
        rows.truncate(n);
    }
    let secs = window.num_seconds();
    rows.into_iter()
        .enumerate()
        .map(|(i, ((a, b), count))| {
            record(
                KIND_PAIR,
                source_at(spans, i),
                json!({
                    "field": field,
                    "a": a,
                    "b": b,
                    "count": count,
                    "window_secs": secs,
                }),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-30T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn since_accepts_durations_timestamps_and_dates() {
        assert_eq!(parse_since("2d", now()).unwrap(), now() - Duration::days(2));
        assert_eq!(
            parse_since("90m", now()).unwrap(),
            now() - Duration::minutes(90)
        );
        assert_eq!(
            parse_since("2026-10-02T09:00:00Z", now()).unwrap(),
            DateTime::parse_from_rfc3339("2026-10-02T09:00:00Z").unwrap()
        );
        assert_eq!(
            parse_since("2026-10-02", now()).unwrap(),
            DateTime::parse_from_rfc3339("2026-10-02T00:00:00Z").unwrap()
        );
    }

    #[test]
    fn since_and_window_refuse_the_unreadable_and_zero() {
        for bad in [
            "",
            "5x",
            "d",
            "0d",
            "-1d",
            "1.5h",
            "yesterday",
            "2026-13-40",
        ] {
            assert!(parse_since(bad, now()).is_err(), "{bad:?}");
        }
        for bad in ["", "0s", "soon", "5", "99999999m"] {
            assert!(parse_window(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_window("5m").unwrap(), Duration::minutes(5));
    }

    #[test]
    fn fields_are_checked_as_dotted_paths() {
        assert!(validate_field("operation.id").is_ok());
        assert!(validate_field("_day").is_ok());
        for bad in ["", "a..b", ".a", "a."] {
            assert!(validate_field(bad).is_err(), "{bad:?}");
        }
    }
}
