//! `diff-spec`: compare two OpenAPI documents operation by operation.
//!
//! An operation is identified by its path and method. Operations only in the
//! new file are added, operations only in the old file are removed, and an
//! operation in both is changed when its operationId, parameters, request
//! body or responses differ in shape. Descriptions, titles and examples are
//! ignored (except where they are field names inside a `properties` map), so a
//! documentation edit is not reported as an API change. A
//! `$ref` is compared as a reference; the component schemas it points at
//! are compared separately, by name, in the schemas line.
//!
//! The report is sorted by path and method, so the same two inputs give the
//! same output.

use std::collections::{BTreeMap, BTreeSet};

use openapiv3::{OpenAPI, Operation, Parameter, PathItem, ReferenceOr};
use serde_json::Value;

/// One operation, reduced to what the comparison looks at.
struct Op {
    id: String,
    /// `"<location> <name>"` to (required, shape without `required`).
    params: BTreeMap<String, (bool, Value)>,
    /// Status code (or `default`) to response shape.
    responses: BTreeMap<String, Value>,
    /// `None` when there is no request body; else content type to schema.
    body: Option<BTreeMap<String, Value>>,
}

/// An operation present in only one file.
pub struct Listed {
    pub method: String,
    pub path: String,
    pub id: String,
}

/// An operation present in both files whose shape differs.
pub struct Changed {
    pub method: String,
    pub path: String,
    /// The operationId in the new file.
    pub id: String,
    pub details: Vec<String>,
}

pub struct SpecDiff {
    pub added: Vec<Listed>,
    pub removed: Vec<Listed>,
    pub changed: Vec<Changed>,
    pub unchanged: usize,
    pub schemas_added: Vec<String>,
    pub schemas_removed: Vec<String>,
    pub schemas_changed: Vec<String>,
}

/// Keys that are documentation wherever they appear as a key of a schema,
/// operation, parameter, response or media type object.
const DOC_KEYS: [&str; 5] = ["description", "title", "example", "examples", "summary"];

/// Remove prose that does not change the shape of an API.
///
/// Inside a `properties` map the keys are field names, so a property called
/// `description` or `title` is kept; only the schema objects it holds are
/// stripped. `in_properties` says the object being visited is such a map.
fn strip_docs(v: &mut Value, in_properties: bool) {
    match v {
        Value::Object(map) => {
            if !in_properties {
                for key in DOC_KEYS {
                    map.remove(key);
                }
            }
            for (key, child) in map.iter_mut() {
                strip_docs(child, !in_properties && key == "properties");
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|c| strip_docs(c, false)),
        _ => {}
    }
}

fn shape<T: serde::Serialize>(item: &T) -> Value {
    let mut v = serde_json::to_value(item).unwrap_or(Value::Null);
    strip_docs(&mut v, false);
    v
}

fn operations(item: &PathItem) -> Vec<(&'static str, &Operation)> {
    [
        ("GET", &item.get),
        ("PUT", &item.put),
        ("POST", &item.post),
        ("DELETE", &item.delete),
        ("OPTIONS", &item.options),
        ("HEAD", &item.head),
        ("PATCH", &item.patch),
        ("TRACE", &item.trace),
    ]
    .into_iter()
    .filter_map(|(m, op)| op.as_ref().map(|op| (m, op)))
    .collect()
}

fn param_entry(p: &ReferenceOr<Parameter>) -> (String, (bool, Value)) {
    match p {
        ReferenceOr::Reference { reference } => (format!("ref {reference}"), (false, Value::Null)),
        ReferenceOr::Item(param) => {
            let (location, data) = match param {
                Parameter::Query { parameter_data, .. } => ("query", parameter_data),
                Parameter::Header { parameter_data, .. } => ("header", parameter_data),
                Parameter::Path { parameter_data, .. } => ("path", parameter_data),
                Parameter::Cookie { parameter_data, .. } => ("cookie", parameter_data),
            };
            let mut v = shape(param);
            if let Value::Object(map) = &mut v {
                map.remove("required");
            }
            (format!("{location} {}", data.name), (data.required, v))
        }
    }
}

fn build(op: &Operation, item: &PathItem) -> Op {
    // Path-level parameters first; an operation-level one of the same
    // location and name replaces it.
    let mut params = BTreeMap::new();
    for p in item.parameters.iter().chain(op.parameters.iter()) {
        let (key, value) = param_entry(p);
        params.insert(key, value);
    }

    let mut responses = BTreeMap::new();
    for (status, resp) in &op.responses.responses {
        responses.insert(status.to_string(), shape(resp));
    }
    if let Some(resp) = &op.responses.default {
        responses.insert("default".to_string(), shape(resp));
    }

    let body = op.request_body.as_ref().map(|rb| match rb {
        ReferenceOr::Reference { reference } => {
            BTreeMap::from([("ref".to_string(), Value::String(reference.clone()))])
        }
        ReferenceOr::Item(rb) => rb
            .content
            .iter()
            .map(|(ct, media)| (ct.clone(), shape(&media.schema)))
            .collect(),
    });

    Op {
        id: op.operation_id.clone().unwrap_or_default(),
        params,
        responses,
        body,
    }
}

/// `(path, METHOD)` to operation.
fn collect(spec: &OpenAPI) -> BTreeMap<(String, String), Op> {
    let mut out = BTreeMap::new();
    for (path, item) in &spec.paths.paths {
        let ReferenceOr::Item(item) = item else {
            continue;
        };
        for (method, op) in operations(item) {
            out.insert((path.clone(), method.to_string()), build(op, item));
        }
    }
    out
}

fn schemas(spec: &OpenAPI) -> BTreeMap<String, Value> {
    spec.components
        .as_ref()
        .map(|c| {
            c.schemas
                .iter()
                .map(|(name, schema)| (name.clone(), shape(schema)))
                .collect()
        })
        .unwrap_or_default()
}

fn changes(old: &Op, new: &Op) -> Vec<String> {
    let mut out = Vec::new();
    if old.id != new.id {
        out.push(format!("operationId: {} -> {}", old.id, new.id));
    }

    let keys: BTreeSet<&String> = old.params.keys().chain(new.params.keys()).collect();
    for key in keys {
        match (old.params.get(key), new.params.get(key)) {
            (None, Some(_)) => out.push(format!("parameter added: {key}")),
            (Some(_), None) => out.push(format!("parameter removed: {key}")),
            (Some((old_req, old_shape)), Some((new_req, new_shape))) => {
                if old_req != new_req {
                    out.push(if *new_req {
                        format!("parameter now required: {key}")
                    } else {
                        format!("parameter no longer required: {key}")
                    });
                }
                if old_shape != new_shape {
                    out.push(format!("parameter changed: {key}"));
                }
            }
            (None, None) => {}
        }
    }

    match (&old.body, &new.body) {
        (None, Some(_)) => out.push("request body added".to_string()),
        (Some(_), None) => out.push("request body removed".to_string()),
        (Some(old_body), Some(new_body)) => {
            let types: BTreeSet<&String> = old_body.keys().chain(new_body.keys()).collect();
            for ct in types {
                match (old_body.get(ct), new_body.get(ct)) {
                    (None, Some(_)) => {
                        out.push(format!("request body content type added: {ct}"));
                    }
                    (Some(_), None) => {
                        out.push(format!("request body content type removed: {ct}"));
                    }
                    (Some(a), Some(b)) if a != b => {
                        out.push(format!("request body changed: {ct}"));
                    }
                    _ => {}
                }
            }
        }
        (None, None) => {}
    }

    let statuses: BTreeSet<&String> = old.responses.keys().chain(new.responses.keys()).collect();
    for status in statuses {
        match (old.responses.get(status), new.responses.get(status)) {
            (None, Some(_)) => out.push(format!("response added: {status}")),
            (Some(_), None) => out.push(format!("response removed: {status}")),
            (Some(a), Some(b)) if a != b => out.push(format!("response changed: {status}")),
            _ => {}
        }
    }
    out
}

pub fn diff(old: &OpenAPI, new: &OpenAPI) -> SpecDiff {
    let old_ops = collect(old);
    let new_ops = collect(new);
    let mut result = SpecDiff {
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
        unchanged: 0,
        schemas_added: Vec::new(),
        schemas_removed: Vec::new(),
        schemas_changed: Vec::new(),
    };

    for ((path, method), op) in &new_ops {
        match old_ops.get(&(path.clone(), method.clone())) {
            None => result.added.push(Listed {
                method: method.clone(),
                path: path.clone(),
                id: op.id.clone(),
            }),
            Some(prev) => {
                let details = changes(prev, op);
                if details.is_empty() {
                    result.unchanged += 1;
                } else {
                    result.changed.push(Changed {
                        method: method.clone(),
                        path: path.clone(),
                        id: op.id.clone(),
                        details,
                    });
                }
            }
        }
    }
    for ((path, method), op) in &old_ops {
        if !new_ops.contains_key(&(path.clone(), method.clone())) {
            result.removed.push(Listed {
                method: method.clone(),
                path: path.clone(),
                id: op.id.clone(),
            });
        }
    }

    let old_schemas = schemas(old);
    let new_schemas = schemas(new);
    for (name, value) in &new_schemas {
        match old_schemas.get(name) {
            None => result.schemas_added.push(name.clone()),
            Some(prev) if prev != value => result.schemas_changed.push(name.clone()),
            Some(_) => {}
        }
    }
    for name in old_schemas.keys() {
        if !new_schemas.contains_key(name) {
            result.schemas_removed.push(name.clone());
        }
    }
    result
}

fn schema_part(count: &[String], word: &str) -> Option<String> {
    (!count.is_empty()).then(|| format!("{} {word} ({})", count.len(), count.join(", ")))
}

pub fn render(d: &SpecDiff) -> String {
    let mut blocks: Vec<String> = Vec::new();

    if !d.added.is_empty() {
        let mut s = format!("added ({})", d.added.len());
        for o in &d.added {
            s.push_str(&format!("\n  + {} {}  {}", o.method, o.path, o.id));
        }
        blocks.push(s);
    }
    if !d.removed.is_empty() {
        let mut s = format!("removed ({})", d.removed.len());
        for o in &d.removed {
            s.push_str(&format!("\n  - {} {}  {}", o.method, o.path, o.id));
        }
        blocks.push(s);
    }
    if !d.changed.is_empty() {
        let mut s = format!("changed ({})", d.changed.len());
        for o in &d.changed {
            s.push_str(&format!("\n  ~ {} {}  {}", o.method, o.path, o.id));
            for detail in &o.details {
                s.push_str(&format!("\n      {detail}"));
            }
        }
        blocks.push(s);
    }

    let parts: Vec<String> = [
        schema_part(&d.schemas_added, "added"),
        schema_part(&d.schemas_removed, "removed"),
        schema_part(&d.schemas_changed, "changed"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !parts.is_empty() {
        blocks.push(format!("schemas: {}", parts.join(", ")));
    }

    if blocks.is_empty() {
        blocks.push("no differences".to_string());
    }
    blocks.push(format!(
        "summary: {} added, {} removed, {} changed, {} unchanged",
        d.added.len(),
        d.removed.len(),
        d.changed.len(),
        d.unchanged
    ));
    let mut out = blocks.join("\n\n");
    out.push('\n');
    out
}
