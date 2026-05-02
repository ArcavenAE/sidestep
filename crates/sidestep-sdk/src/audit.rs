//! JSONL audit trail emission.
//!
//! Schema lives in `docs/audit-trail-format.md`. v0.1 implements
//! schema_version=1 with the documented fields and a header-only
//! redaction policy (see `redact.rs`).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::TokenSource;
use crate::error::Result;
use crate::redact;

/// Returns the configured audit directory, or `None` if the trail is
/// globally disabled (`SIDESTEP_AUDIT=off`).
pub fn audit_dir() -> Option<PathBuf> {
    if std::env::var("SIDESTEP_AUDIT").is_ok_and(|v| v.eq_ignore_ascii_case("off")) {
        return None;
    }
    if let Ok(custom) = std::env::var("SIDESTEP_AUDIT_DIR") {
        return Some(PathBuf::from(custom));
    }
    if let Some(state) = dirs::state_dir() {
        return Some(state.join("sidestep").join("audit"));
    }
    if let Some(home) = dirs::home_dir() {
        return Some(home.join(".sidestep").join("audit"));
    }
    None
}

#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Ok,
    HttpError,
    NetworkError,
    AuthError,
    RedactedBlock,
}

impl Outcome {
    fn as_str(&self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::HttpError => "http_error",
            Outcome::NetworkError => "network_error",
            Outcome::AuthError => "auth_error",
            Outcome::RedactedBlock => "redacted_block",
        }
    }
}

/// One audit emission per HTTP call or stream-transform verb.
/// Construct via `Span::start`. Finish via `finish` (API-shape) or
/// `finish_as_verb` (verb-shape, no operation/response/outcome).
/// Drop without finish is a bug; if it happens we lose the line
/// silently (we don't want a panic in the audit path).
pub struct Span {
    pub trace_id: Uuid,
    pub span_id: Uuid,
    pub parent_span_id: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub argv_redacted: Vec<String>,
    pub binary_version: &'static str,
    pub host: String,
    pub user: String,
    pub tty: bool,
    pub auth_source: Option<TokenSource>,
    pub op: Option<AuditOp>,

    /// Verb-phase tag — `list`, `get`, `search`, `api`, `filter`,
    /// `enrich`, `emit`. Emitted as the v2 `verb_phase` audit field.
    /// `None` means "treat as legacy" (the v1 emission shape).
    pub verb_phase: Option<&'static str>,

    /// Per-record synthesis keys — e.g. `["id"]` for kinds keyed on
    /// `id`. Surfaced in the v2 audit so miners can join records
    /// across runs without re-deriving the kind's primary key.
    pub synthesis_keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditOp {
    pub id: String,
    pub method: String,
    pub url_template: String,
    pub path_params: Value,
    pub query_params: Value,
}

pub struct Outcomes {
    pub outcome: Outcome,
    pub status: Option<u16>,
    pub size_bytes: Option<usize>,
    pub items_returned: Option<usize>,
    pub next_cursor: Option<String>,
    pub shape_hash: Option<String>,
    pub redacted_fields: Vec<String>,
}

impl Span {
    /// Construct a span with a fresh UUIDv7 trace_id. Most callers
    /// want this — only the SDK Client uses [`Span::start`] directly
    /// to allow `CallOptions::trace_id` to thread through.
    pub fn start_fresh() -> Self {
        Self::start(Uuid::now_v7())
    }

    pub fn start(trace_id: Uuid) -> Self {
        let argv: Vec<String> = std::env::args().collect();
        let argv_redacted = redact::redact_argv(&argv);
        Self {
            trace_id,
            span_id: Uuid::now_v7(),
            parent_span_id: None,
            started_at: Utc::now(),
            argv_redacted,
            binary_version: env!("CARGO_PKG_VERSION"),
            host: hostname(),
            user: std::env::var("USER").unwrap_or_default(),
            tty: std::io::IsTerminal::is_terminal(&std::io::stdout()),
            auth_source: None,
            op: None,
            verb_phase: None,
            synthesis_keys: Vec::new(),
        }
    }

    pub fn with_op(mut self, op: AuditOp) -> Self {
        self.op = Some(op);
        self
    }

    pub fn with_verb_phase(mut self, phase: &'static str) -> Self {
        self.verb_phase = Some(phase);
        self
    }

    pub fn with_synthesis_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.synthesis_keys = keys.into_iter().map(Into::into).collect();
        self
    }

    /// Build an API-shape JSONL record and write it. Best-effort: any
    /// IO failure is swallowed to a `tracing::warn` so audit failures
    /// don't break the user's command.
    pub fn finish(self, outcomes: Outcomes) {
        let ts_end = Utc::now();
        let duration_ms = (ts_end - self.started_at).num_milliseconds().max(0) as u64;

        let mut record = self.base_record(duration_ms);
        record["result"] = json!(outcomes.outcome.as_str());
        record["redacted_fields"] = json!(outcomes.redacted_fields);

        if let Some(op) = &self.op {
            record["operation"] = serde_json::to_value(op).unwrap_or(Value::Null);
        }

        let mut response = serde_json::Map::new();
        if let Some(s) = outcomes.status {
            response.insert("status".into(), json!(s));
        }
        if let Some(b) = outcomes.size_bytes {
            response.insert("size_bytes".into(), json!(b));
        }
        if let Some(n) = outcomes.items_returned {
            response.insert("items_returned".into(), json!(n));
        }
        if let Some(c) = outcomes.next_cursor {
            response.insert("next_cursor".into(), json!(c));
        }
        if let Some(h) = outcomes.shape_hash {
            response.insert("shape_hash".into(), json!(h));
        }
        if !response.is_empty() {
            record["response"] = Value::Object(response);
        }

        if let Err(e) = write_line(&record) {
            tracing::warn!(error = %e, "audit emission failed");
        }
    }

    /// Build a verb-shape JSONL record and write it. Used by stream
    /// transforms (`filter`, `enrich`, `emit`) that have no API call.
    /// `extra` carries verb-specific fields — `predicate_text`,
    /// `predicate_outcome`, `recipe_id`, etc.
    pub fn finish_as_verb(self, extra: serde_json::Map<String, Value>) {
        let ts_end = Utc::now();
        let duration_ms = (ts_end - self.started_at).num_milliseconds().max(0) as u64;

        let mut record = self.base_record(duration_ms);
        for (k, v) in extra {
            record[k] = v;
        }

        if let Err(e) = write_line(&record) {
            tracing::warn!(error = %e, "audit emission failed");
        }
    }

    /// Common header shared by API and verb emissions. v2 schema:
    /// adds `verb_phase` and `synthesis_keys` when present, leaves
    /// outcome/response detail to the caller.
    fn base_record(&self, duration_ms: u64) -> Value {
        let mut record = json!({
            "schema_version": 2,
            "trace_id": self.trace_id.to_string(),
            "span_id": self.span_id.to_string(),
            "parent_span_id": self.parent_span_id.map(|u| u.to_string()),
            "ts_start": self.started_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "duration_ms": duration_ms,
            "invocation": {
                "argv": self.argv_redacted,
                "binary_version": self.binary_version,
                "host": self.host,
                "user": self.user,
                "tty": self.tty,
                "auth_source": self.auth_source.map(|s| s.as_str()),
            },
        });
        if let Some(p) = self.verb_phase {
            record["verb_phase"] = json!(p);
        }
        if !self.synthesis_keys.is_empty() {
            record["synthesis_keys"] = json!(self.synthesis_keys);
        }
        record
    }
}

fn write_line(record: &Value) -> Result<()> {
    let Some(dir) = audit_dir() else {
        return Ok(());
    };
    std::fs::create_dir_all(&dir)?;
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let path = dir.join(format!("{today}.jsonl"));
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let line = serde_json::to_string(record)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default()
}

/// Compute a sha256 over a "shape view" of a JSON value (keys and types,
/// not values). Used for `response.shape_hash` so pattern detection can
/// see schema drift without storing payloads.
pub fn shape_hash(v: &Value) -> String {
    use sha2::{Digest, Sha256};
    let shape = shape_string(v);
    let mut hasher = Sha256::new();
    hasher.update(shape.as_bytes());
    format!("sha256:{}", hex_encode(&hasher.finalize()))
}

fn shape_string(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "bool".to_string(),
        Value::Number(_) => "num".to_string(),
        Value::String(_) => "str".to_string(),
        Value::Array(items) => {
            // Use the union of element shapes; arrays of mixed kinds
            // collapse to "arr<a|b|...>".
            let mut variants: Vec<String> = items.iter().map(shape_string).collect();
            variants.sort();
            variants.dedup();
            format!("arr<{}>", variants.join("|"))
        }
        Value::Object(map) => {
            let mut keys: Vec<(String, String)> = map
                .iter()
                .map(|(k, v)| (k.clone(), shape_string(v)))
                .collect();
            keys.sort_by(|a, b| a.0.cmp(&b.0));
            let body: Vec<String> = keys.into_iter().map(|(k, t)| format!("{k}:{t}")).collect();
            format!("obj{{{}}}", body.join(","))
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("write to String");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_hash_is_value_independent() {
        let a = json!({"name": "alice", "age": 30});
        let b = json!({"name": "bob", "age": 99});
        assert_eq!(shape_hash(&a), shape_hash(&b));
    }

    #[test]
    fn shape_hash_changes_when_keys_differ() {
        let a = json!({"name": "alice"});
        let b = json!({"alias": "alice"});
        assert_ne!(shape_hash(&a), shape_hash(&b));
    }

    #[test]
    fn shape_hash_changes_when_types_differ() {
        let a = json!({"id": "1"});
        let b = json!({"id": 1});
        assert_ne!(shape_hash(&a), shape_hash(&b));
    }
}
