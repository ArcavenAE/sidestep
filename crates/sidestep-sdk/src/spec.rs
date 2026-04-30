//! Operation registry built from the vendored OpenAPI spec.
//!
//! The spec is embedded at compile time via `include_str!`. Parsing
//! happens once on first access, cached in `OnceLock`.

use std::collections::HashMap;
use std::sync::OnceLock;

use openapiv3::{OpenAPI, Operation, Parameter, PathItem, ReferenceOr, RequestBody};

use crate::error::{Result, SidestepError};

const SPEC_YAML: &str = include_str!("../../../spec/stepsecurity-v1.yaml");

pub fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(|| {
        Registry::load().unwrap_or_else(|e| panic!("vendored spec failed to parse: {e}"))
    })
}

#[derive(Debug)]
pub struct Registry {
    pub base_url: String,
    ops: HashMap<String, OperationMeta>,
}

#[derive(Clone, Debug)]
pub struct OperationMeta {
    pub id: String,
    pub method: HttpMethod,
    pub path_template: String,
    /// Path parameter names (substituted into `{name}` placeholders).
    pub path_params: Vec<String>,
    /// Query parameter names.
    pub query_params: Vec<String>,
    /// Required path + query parameter names. Used to validate input.
    pub required_params: Vec<String>,
    /// True if the operation accepts a request body (POST/PUT/PATCH/DELETE
    /// with `requestBody` declared).
    pub has_body: bool,
    /// Brief one-line description from the spec, when available.
    pub summary: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Put,
    Post,
    Delete,
    Options,
    Head,
    Patch,
    Trace,
}

impl HttpMethod {
    pub fn as_reqwest(&self) -> reqwest::Method {
        match self {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Options => reqwest::Method::OPTIONS,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Trace => reqwest::Method::TRACE,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Put => "PUT",
            HttpMethod::Post => "POST",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Head => "HEAD",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Trace => "TRACE",
        }
    }
}

impl Registry {
    fn load() -> Result<Self> {
        let spec: OpenAPI = serde_yaml::from_str(SPEC_YAML)
            .map_err(|e| SidestepError::Spec(format!("yaml parse: {e}")))?;
        let base_url = spec
            .servers
            .first()
            .map(|s| s.url.trim_end_matches('/').to_string())
            .unwrap_or_else(|| "https://agent.api.stepsecurity.io/v1".to_string());

        let mut ops = HashMap::new();
        for (path, item_ref) in spec.paths.paths.iter() {
            let ReferenceOr::Item(item) = item_ref else {
                continue;
            };
            for (method, op) in operations(item) {
                let Some(id) = op.operation_id.clone() else {
                    continue;
                };
                let meta = build_meta(id.clone(), method, path.as_str(), op);
                ops.insert(id, meta);
            }
        }
        Ok(Self { base_url, ops })
    }

    pub fn find(&self, id: &str) -> Result<&OperationMeta> {
        self.ops
            .get(id)
            .ok_or_else(|| SidestepError::UnknownOperation(id.to_string()))
    }

    pub fn iter(&self) -> impl Iterator<Item = &OperationMeta> {
        self.ops.values()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

fn operations(item: &PathItem) -> Vec<(HttpMethod, &Operation)> {
    let mut out: Vec<(HttpMethod, &Operation)> = Vec::new();
    if let Some(op) = &item.get {
        out.push((HttpMethod::Get, op));
    }
    if let Some(op) = &item.put {
        out.push((HttpMethod::Put, op));
    }
    if let Some(op) = &item.post {
        out.push((HttpMethod::Post, op));
    }
    if let Some(op) = &item.delete {
        out.push((HttpMethod::Delete, op));
    }
    if let Some(op) = &item.options {
        out.push((HttpMethod::Options, op));
    }
    if let Some(op) = &item.head {
        out.push((HttpMethod::Head, op));
    }
    if let Some(op) = &item.patch {
        out.push((HttpMethod::Patch, op));
    }
    if let Some(op) = &item.trace {
        out.push((HttpMethod::Trace, op));
    }
    out
}

fn build_meta(id: String, method: HttpMethod, path: &str, op: &Operation) -> OperationMeta {
    let mut path_params = Vec::new();
    let mut query_params = Vec::new();
    let mut required_params = Vec::new();

    for p in &op.parameters {
        let ReferenceOr::Item(p) = p else { continue };
        match p {
            Parameter::Path { parameter_data, .. } => {
                path_params.push(parameter_data.name.clone());
                if parameter_data.required {
                    required_params.push(parameter_data.name.clone());
                }
            }
            Parameter::Query { parameter_data, .. } => {
                query_params.push(parameter_data.name.clone());
                if parameter_data.required {
                    required_params.push(parameter_data.name.clone());
                }
            }
            // Header / Cookie parameters intentionally not surfaced in v0.1.
            _ => {}
        }
    }

    let has_body = match &op.request_body {
        Some(ReferenceOr::Item(RequestBody { content, .. })) => !content.is_empty(),
        Some(ReferenceOr::Reference { .. }) => true,
        None => false,
    };

    OperationMeta {
        id,
        method,
        path_template: path.to_string(),
        path_params,
        query_params,
        required_params,
        has_body,
        summary: op.summary.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_loads_with_expected_op_count() {
        let r = registry();
        // Vendored spec has 97 operationIds (15 explicit + 78 synthesized
        // + 4 spec drift between sessions). We assert >= 90 so this test
        // doesn't break on minor upstream additions.
        assert!(r.len() >= 90, "expected >= 90 ops, got {}", r.len());
        assert!(r.base_url.starts_with("https://"));
    }

    #[test]
    fn registry_finds_a_well_known_op() {
        let r = registry();
        // getRunsDetails is one of the explicitly-named ops in the StepSecurity spec.
        let op = r.find("getRunsDetails").expect("getRunsDetails exists");
        assert_eq!(op.method, HttpMethod::Get);
        assert!(op.path_template.contains("/runs"));
        assert!(op.path_params.contains(&"owner".to_string()));
        assert!(op.required_params.contains(&"owner".to_string()));
    }

    #[test]
    fn registry_unknown_op_errors() {
        let r = registry();
        assert!(r.find("definitelyNotARealOp").is_err());
    }
}
