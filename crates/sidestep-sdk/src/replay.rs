//! `replay`: read the audit spans one trace id produced.
//!
//! This is the audit trail's read path. It returns what was called and
//! the shape of each response (operation, parameters, status, size,
//! `shape_hash`), not the records: the trail stores no payloads, so
//! there is nothing to re-emit. Reading a trace back never touches the
//! network.
//!
//! Each matching span is wrapped as a stream record
//! (`_kind: "audit_span"`, `_source.operation_id: "audit_trail"`,
//! `_source.trace_ref: "<trace_id>:<span_id>"`) with the span's own
//! fields alongside, so the other verbs (`filter`, `rank`, `diff`) work
//! on it. Spans come out in `ts_start` order across all files; spans
//! with the same `ts_start` keep file and line order.
//!
//! Lines that are blank are ignored. Lines that do not parse as a JSON
//! object are counted, not hidden, so a damaged trail shows in the
//! outcome.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::stream::{Record, SourceRef};

/// `_kind` of a replayed span.
pub const KIND_AUDIT_SPAN: &str = "audit_span";
/// `_source.operation_id` of a replayed span: it came from the trail,
/// not from an API call.
pub const SOURCE_AUDIT_TRAIL: &str = "audit_trail";

/// What a read of the trail found.
#[derive(Debug)]
pub struct Replayed {
    pub records: Vec<Record>,
    pub files_read: usize,
    pub lines_unparsed: usize,
}

/// A trace id is a UUID or ULID: letters, digits and hyphens, bounded.
/// Anything else is refused before the trail is opened, so a crafted id
/// cannot be read as a path or a pattern.
pub fn validate_trace_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "trace id {id:?} is not valid: expected letters, digits and hyphens, up to 64 characters"
        ))
    }
}

/// Read every `*.jsonl` file in `dir` and collect the spans whose
/// `trace_id` is `trace_id`.
pub fn read_trace(dir: &Path, trace_id: &str) -> Result<Replayed, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("read audit trail directory {}: {e}", dir.display()))?;
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("jsonl"))
        .collect();
    files.sort();

    // (ts_start, file index, line index, record): the last two keep the
    // order stable when two spans share a timestamp.
    let mut found: Vec<(String, usize, usize, Record)> = Vec::new();
    let mut lines_unparsed = 0usize;
    for (fi, path) in files.iter().enumerate() {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("read audit trail file {}: {e}", path.display()))?;
        let text = String::from_utf8_lossy(&bytes);
        for (li, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(Value::Object(span)) = serde_json::from_str::<Value>(line) else {
                lines_unparsed += 1;
                continue;
            };
            if span.get("trace_id").and_then(Value::as_str) != Some(trace_id) {
                continue;
            }
            let ts = span
                .get("ts_start")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let fetched_at = DateTime::parse_from_rfc3339(&ts)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let span_id = span
                .get("span_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let record = Record {
                kind: KIND_AUDIT_SPAN.to_string(),
                source: SourceRef {
                    operation_id: SOURCE_AUDIT_TRAIL.to_string(),
                    response_index: found.len(),
                    fetched_at,
                    trace_ref: Some(format!("{trace_id}:{span_id}")),
                },
                fields: span,
            };
            found.push((ts, fi, li, record));
        }
    }
    found.sort_by(|a, b| (&a.0, a.1, a.2).cmp(&(&b.0, b.1, b.2)));
    let records = found
        .into_iter()
        .enumerate()
        .map(|(i, (_, _, _, mut r))| {
            r.source.response_index = i;
            r
        })
        .collect();
    Ok(Replayed {
        records,
        files_read: files.len(),
        lines_unparsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_ids_are_bounded_to_safe_characters() {
        assert!(validate_trace_id("01900000-0000-7000-8000-000000000001").is_ok());
        assert!(validate_trace_id("01HXYABCDEF0123456789").is_ok());
        for bad in ["", "../x", "a/b", "a b", "a;b", &"x".repeat(65)] {
            assert!(validate_trace_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_unreadable_directory_is_an_error_naming_it() {
        let err = read_trace(Path::new("/nonexistent-sidestep-trail"), "t").unwrap_err();
        assert!(err.contains("/nonexistent-sidestep-trail"), "{err}");
    }
}
