//! SDK client. Spec-aware HTTP execution against the StepSecurity API.

use std::collections::BTreeMap;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::Value;
use uuid::Uuid;

use crate::audit::{AuditOp, Outcome, Outcomes, Span, shape_hash};
use crate::auth::{self, ParamSource, TokenSource};
use crate::error::{Result, SidestepError};
use crate::spec::{OperationMeta, registry};

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base_url: String,
    auth_source: Option<TokenSource>,
}

#[derive(Clone, Debug, Default)]
pub struct CallOptions {
    /// Trace ID to attach to the audit span. If `None`, a fresh UUIDv7
    /// is generated. Pass an existing trace_id to group multiple calls
    /// (e.g. paginated reads) under one logical operation.
    pub trace_id: Option<Uuid>,
    /// If true, the SDK records a stub audit line marked
    /// `result=redacted_block` instead of the operation detail.
    pub no_audit: bool,
    /// Verb-phase tag for the audit emission. CLI primitives set this
    /// (`list`, `get`, `search`, `api`); leave `None` for the legacy
    /// shape if you're driving the SDK directly without a CLI verb.
    pub verb_phase: Option<&'static str>,
    /// Per-record synthesis keys for the v2 audit. Typically the
    /// kind's primary key field, e.g. `["id"]`.
    pub synthesis_keys: Vec<String>,
    /// Provenance of each path parameter the caller resolved through
    /// the val-resolution-chain (flag → env → config). Used by the CLI
    /// for `owner` / `customer`. Recorded in the audit emission as the
    /// `path_params_source` sibling of `operation`. Params not present
    /// here are treated as flag/explicit and produce no source entry.
    pub path_params_source: BTreeMap<String, ParamSource>,
}

impl Client {
    /// Resolve a token via env → keyring and construct a Client.
    pub fn from_env() -> Result<Self> {
        let resolved = auth::resolve()?;
        Self::build(&resolved.token, Some(resolved.source))
    }

    /// Construct with an explicit token (skips the resolver chain). The
    /// audit trail records `auth_source` as `None` for this path.
    pub fn with_token(token: &str) -> Result<Self> {
        Self::build(token, None)
    }

    fn build(token: &str, auth_source: Option<TokenSource>) -> Result<Self> {
        let mut headers = HeaderMap::new();
        let auth = format!("Bearer {token}");
        let mut auth_value = HeaderValue::from_str(&auth)
            .map_err(|_| SidestepError::Auth("invalid token characters".into()))?;
        auth_value.set_sensitive(true);
        headers.insert(reqwest::header::AUTHORIZATION, auth_value);
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_static(concat!("sidestep/", env!("CARGO_PKG_VERSION"))),
        );

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| SidestepError::Network(e.to_string()))?;

        let base_url = registry().base_url.clone();
        Ok(Self {
            http,
            base_url,
            auth_source,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn auth_source(&self) -> Option<TokenSource> {
        self.auth_source
    }

    /// Execute an operation by ID. `params` is a JSON object whose
    /// fields are mapped to path / query parameters per the spec.
    /// Body content goes under the `body` key.
    pub async fn call_op(
        &self,
        operation_id: &str,
        params: &Value,
        opts: CallOptions,
    ) -> Result<Value> {
        let op = registry().find(operation_id)?.clone();
        let trace_id = opts.trace_id.unwrap_or_else(Uuid::now_v7);
        let mut span = Span::start(trace_id);
        span.auth_source = self.auth_source;
        if let Some(phase) = opts.verb_phase {
            span = span.with_verb_phase(phase);
        }
        if !opts.synthesis_keys.is_empty() {
            span = span.with_synthesis_keys(opts.synthesis_keys.clone());
        }
        if !opts.path_params_source.is_empty() {
            span = span.with_path_params_source(opts.path_params_source.clone());
        }

        if opts.no_audit {
            self.execute_silent(&op, params, span).await
        } else {
            let audit_op = audit_op_from(&op, params);
            span = span.with_op(audit_op);
            self.execute_audited(&op, params, span).await
        }
    }

    async fn execute_audited(
        &self,
        op: &OperationMeta,
        params: &Value,
        span: Span,
    ) -> Result<Value> {
        let result = self.send(op, params).await;
        let outcomes = match &result {
            Ok((value, status)) => Outcomes {
                outcome: Outcome::Ok,
                status: Some(*status),
                size_bytes: Some(estimated_size(value)),
                items_returned: count_items(value),
                next_cursor: extract_cursor(value),
                shape_hash: Some(shape_hash(value)),
                redacted_fields: vec!["authorization".to_string()],
            },
            Err(SidestepError::Http { status, body }) => Outcomes {
                outcome: Outcome::HttpError,
                status: Some(*status),
                size_bytes: Some(body.len()),
                items_returned: None,
                next_cursor: None,
                shape_hash: None,
                redacted_fields: vec!["authorization".to_string()],
            },
            Err(SidestepError::Network(_)) => Outcomes {
                outcome: Outcome::NetworkError,
                status: None,
                size_bytes: None,
                items_returned: None,
                next_cursor: None,
                shape_hash: None,
                redacted_fields: vec!["authorization".to_string()],
            },
            Err(SidestepError::Auth(_)) => Outcomes {
                outcome: Outcome::AuthError,
                status: None,
                size_bytes: None,
                items_returned: None,
                next_cursor: None,
                shape_hash: None,
                redacted_fields: vec!["authorization".to_string()],
            },
            Err(_) => Outcomes {
                outcome: Outcome::HttpError,
                status: None,
                size_bytes: None,
                items_returned: None,
                next_cursor: None,
                shape_hash: None,
                redacted_fields: vec!["authorization".to_string()],
            },
        };
        span.finish(outcomes);
        result.map(|(value, _)| value)
    }

    async fn execute_silent(
        &self,
        op: &OperationMeta,
        params: &Value,
        span: Span,
    ) -> Result<Value> {
        let result = self.send(op, params).await;
        span.finish(Outcomes {
            outcome: Outcome::RedactedBlock,
            status: result.as_ref().ok().map(|(_, s)| *s),
            size_bytes: None,
            items_returned: None,
            next_cursor: None,
            shape_hash: None,
            redacted_fields: vec!["operation".to_string(), "response".to_string()],
        });
        result.map(|(value, _)| value)
    }

    async fn send(&self, op: &OperationMeta, params: &Value) -> Result<(Value, u16)> {
        let url = build_url(&self.base_url, op, params)?;
        let mut req = self.http.request(op.method.as_reqwest(), &url);

        // Query parameters
        let mut query: Vec<(String, String)> = Vec::new();
        for q in &op.query_params {
            if let Some(v) = params.get(q) {
                query.push((q.clone(), value_to_query_string(v)));
            }
        }
        if !query.is_empty() {
            req = req.query(&query);
        }

        // Body for write methods
        if op.has_body {
            if let Some(body) = params.get("body") {
                req = req.json(body);
            }
        }

        let response = req
            .send()
            .await
            .map_err(|e| SidestepError::Network(e.to_string()))?;
        let status = response.status();
        let body_text = response
            .text()
            .await
            .map_err(|e| SidestepError::Network(e.to_string()))?;
        let status_code = status.as_u16();

        if !status.is_success() {
            return Err(SidestepError::Http {
                status: status_code,
                body: body_text,
            });
        }

        let value = if body_text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&body_text).unwrap_or_else(|_| Value::String(body_text.clone()))
        };
        Ok((value, status_code))
    }
}

fn build_url(base: &str, op: &OperationMeta, params: &Value) -> Result<String> {
    let mut path = op.path_template.clone();
    for name in &op.path_params {
        let value = params
            .get(name)
            .ok_or_else(|| SidestepError::MissingParam(name.clone(), op.id.clone()))?;
        let s = value_to_path_string(value).ok_or_else(|| {
            SidestepError::InvalidParam(name.clone(), "path params must be scalar".into())
        })?;
        let placeholder = format!("{{{name}}}");
        path = path.replace(&placeholder, &s);
    }
    Ok(format!("{base}{path}"))
}

fn value_to_path_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(urlencoding::encode(s).into_owned()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn value_to_query_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => v.to_string(),
    }
}

fn audit_op_from(op: &OperationMeta, params: &Value) -> AuditOp {
    let mut path_params = serde_json::Map::new();
    for name in &op.path_params {
        if let Some(v) = params.get(name) {
            path_params.insert(name.clone(), v.clone());
        }
    }
    let mut query_params = serde_json::Map::new();
    for name in &op.query_params {
        if let Some(v) = params.get(name) {
            query_params.insert(name.clone(), v.clone());
        }
    }
    AuditOp {
        id: op.id.clone(),
        method: op.method.as_str().to_string(),
        url_template: op.path_template.clone(),
        path_params: Value::Object(path_params),
        query_params: Value::Object(query_params),
    }
}

fn estimated_size(v: &Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)
}

/// If the response is an array or has a top-level array under common
/// pagination keys (`items`, `data`, `results`), return its length.
fn count_items(v: &Value) -> Option<usize> {
    if let Some(arr) = v.as_array() {
        return Some(arr.len());
    }
    for key in ["items", "data", "results", "runs", "detections", "checks"] {
        if let Some(arr) = v.get(key).and_then(|x| x.as_array()) {
            return Some(arr.len());
        }
    }
    None
}

fn extract_cursor(v: &Value) -> Option<String> {
    for key in ["next_cursor", "next", "cursor", "next_page"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}
