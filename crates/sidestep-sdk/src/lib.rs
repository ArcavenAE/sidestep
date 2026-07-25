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
pub mod cel;
pub mod client;
pub mod enrich;
pub mod error;
pub mod kinds;
pub mod redact;
pub mod spec;
pub mod stream;

pub use auth::{ParamSource, ResolvedParam, ResolvedToken, TokenSource};
pub use client::{BASE_URL_ENV, CallOptions, Client};
pub use error::{Result, SidestepError};
pub use kinds::{KindSpec, all_kinds, extract_items, kind_spec};
pub use spec::{HttpMethod, OperationMeta, Registry, registry};
pub use stream::{Record, SourceRef, read_stream, write_record};

pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build identity stamped by `build.rs`: the CI channel tag
/// (`alpha-…`, `v<ver>-rc.N+g<sha7>`, `v<ver>+g<sha7>`), or
/// `dev+g<sha7>[-dirty]` for local builds, or `unknown`.
pub const BUILD_ID: &str = env!("SIDESTEP_BUILD_ID");

/// Full version string for `--version`: semver plus build identity.
pub const FULL_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("SIDESTEP_BUILD_ID"),
    ")"
);
