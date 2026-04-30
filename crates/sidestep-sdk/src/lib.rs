//! sidestep-sdk — the SDK that backs sidestep-cli and (future) sidestep-mcp.
//!
//! Modules:
//!   * `auth`    — token resolution: env → keyring → config file (env-only in v0.1)
//!   * `audit`   — JSONL audit trail (see `docs/audit-trail-format.md`)
//!   * `client`  — `Client::call_op(operation_id, params)` execution surface
//!   * `error`   — `SidestepError` + `Result<T>`
//!   * `redact`  — argv + header redaction policy
//!   * `spec`    — operation registry over the vendored OpenAPI spec

#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod client;
pub mod error;
pub mod redact;
pub mod spec;

pub use client::{CallOptions, Client};
pub use error::{Result, SidestepError};
pub use spec::{HttpMethod, OperationMeta, Registry, registry};

pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
