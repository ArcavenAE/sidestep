//! sidestep-sdk — the SDK that backs sidestep-cli and (future) sidestep-mcp.
//!
//! Module shape (filled in by follow-on tickets):
//!   * `auth`    — token resolution: env → keyring → config file
//!   * `client`  — configured reqwest::Client + base URL + auth header injection
//!   * `audit`   — JSONL audit trail (see `docs/audit-trail-format.md`)
//!   * `redact`  — field-level redaction policy applied before audit emission
//!   * `paginate`— typed cursor/page helpers shared across operations
//!   * `error`   — SidestepError + Result<T>

#![forbid(unsafe_code)]

pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
