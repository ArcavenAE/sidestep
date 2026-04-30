//! Token resolution. v0.1: env-only.
//! Charter F4 will extend this to keyring + config file fallbacks.

use crate::error::{Result, SidestepError};

pub const TOKEN_ENV: &str = "SIDESTEP_API_TOKEN";

pub fn resolve_token() -> Result<String> {
    if let Ok(t) = std::env::var(TOKEN_ENV) {
        if !t.is_empty() {
            return Ok(t);
        }
    }
    Err(SidestepError::Auth(format!(
        "no token found. Set {TOKEN_ENV}=<bearer-token>. \
         Keyring + config file fallbacks are planned (charter F4)."
    )))
}
