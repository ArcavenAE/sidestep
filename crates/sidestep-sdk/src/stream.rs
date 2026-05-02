//! JSON-line stream contract for sidestep primitives.
//!
//! Records flow stdin → stdout between primitives. Every record carries a
//! `_kind` discriminator and a `_source` reference back to the API call
//! that produced it. Domain fields live alongside.
//!
//! Stream contract per `_kos/probes/brief-primitive-layer-v01.md`:
//! `{ _kind: <string>, _source: { operation_id, response_index,
//! fetched_at }, ...domain_fields }`.

use std::io::{BufRead, Write};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Result, SidestepError};

/// One record in a sidestep JSON-line stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    #[serde(rename = "_kind")]
    pub kind: String,

    #[serde(rename = "_source")]
    pub source: SourceRef,

    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

/// Provenance attached to every stream record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    pub operation_id: String,
    pub response_index: usize,
    pub fetched_at: DateTime<Utc>,

    /// Audit-trail pointer (`<trace_id>:<span_id>`). Optional — the
    /// reader-only path (cat-from-fixture) won't have it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_ref: Option<String>,
}

impl SourceRef {
    /// Build a `SourceRef` stamped with `Utc::now()` and no trace pointer.
    /// CLI-side helper so callers don't need to depend on `chrono` directly.
    pub fn now(operation_id: &str, response_index: usize) -> Self {
        Self {
            operation_id: operation_id.to_string(),
            response_index,
            fetched_at: Utc::now(),
            trace_ref: None,
        }
    }
}

impl Record {
    /// Construct a record from a raw JSON object pulled out of an API
    /// response, attaching the discriminator and provenance.
    pub fn wrap(kind: &str, source: SourceRef, body: Value) -> Self {
        let fields = match body {
            Value::Object(map) => map,
            other => {
                let mut m = Map::new();
                m.insert("value".to_string(), other);
                m
            }
        };
        Self {
            kind: kind.to_string(),
            source,
            fields,
        }
    }

    /// Look up a domain field by name. Synthesised meta fields
    /// (`_kind`, `_source`) are not visible here — use `kind()` /
    /// `source()` for those.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.fields.get(name)
    }
}

/// Read records from a JSONL stream. Blank lines are skipped. Any line
/// that fails to parse is returned as an `Err` and stops iteration via
/// the caller's choice.
pub fn read_stream<R: BufRead>(reader: R) -> impl Iterator<Item = Result<Record>> {
    reader.lines().filter_map(|line_res| match line_res {
        Err(e) => Some(Err(SidestepError::from(e))),
        Ok(line) if line.trim().is_empty() => None,
        Ok(line) => Some(serde_json::from_str::<Record>(&line).map_err(SidestepError::from)),
    })
}

/// Write one record as a single JSON line followed by `\n`.
pub fn write_record<W: Write>(w: &mut W, record: &Record) -> Result<()> {
    serde_json::to_writer(&mut *w, record)?;
    w.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn round_trip_a_minimal_record() {
        let mut fields = Map::new();
        fields.insert("id".into(), Value::String("det_001".into()));
        fields.insert("severity".into(), Value::String("high".into()));
        let r = Record {
            kind: "detection".into(),
            source: SourceRef {
                operation_id: "get_github_owner_actions_detections".into(),
                response_index: 0,
                fetched_at: DateTime::parse_from_rfc3339("2026-04-30T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                trace_ref: None,
            },
            fields,
        };

        let mut buf = Vec::new();
        write_record(&mut buf, &r).unwrap();
        let line = String::from_utf8(buf).unwrap();
        assert!(line.starts_with("{"));
        assert!(line.contains("\"_kind\":\"detection\""));
        assert!(line.contains("\"id\":\"det_001\""));
        assert!(!line.contains("trace_ref"));
        assert!(line.ends_with("\n"));

        let parsed: Vec<Record> = read_stream(Cursor::new(line.into_bytes()))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "detection");
        assert_eq!(
            parsed[0].source.operation_id,
            "get_github_owner_actions_detections"
        );
        assert_eq!(parsed[0].get("id"), Some(&Value::String("det_001".into())));
    }

    #[test]
    fn read_stream_skips_blank_lines() {
        let input = "\n\n{\"_kind\":\"detection\",\"_source\":{\"operation_id\":\"op\",\"response_index\":0,\"fetched_at\":\"2026-04-30T10:00:00Z\"},\"id\":\"x\"}\n\n";
        let recs: Vec<Record> = read_stream(Cursor::new(input.as_bytes().to_vec()))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, "detection");
    }

    #[test]
    fn read_stream_propagates_parse_errors() {
        let input = "{not json}\n";
        let result: Result<Vec<Record>> =
            read_stream(Cursor::new(input.as_bytes().to_vec())).collect();
        assert!(result.is_err());
    }

    #[test]
    fn wrap_promotes_non_object_into_value_field() {
        let r = Record::wrap(
            "detection",
            SourceRef {
                operation_id: "op".into(),
                response_index: 0,
                fetched_at: Utc::now(),
                trace_ref: None,
            },
            Value::String("scalar".into()),
        );
        assert_eq!(r.get("value"), Some(&Value::String("scalar".into())));
    }
}
