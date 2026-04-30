//! Token resolution. v0.1: env → platform keyring.
//! Charter F4 partial — config file fallback remains a follow-on.

use serde::Serialize;

use crate::error::{Result, SidestepError};

pub const TOKEN_ENV: &str = "SIDESTEP_API_TOKEN";
pub const KEYRING_SERVICE: &str = "sidestep";
pub const KEYRING_USER: &str = "default";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSource {
    Env,
    Keyring,
}

impl TokenSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenSource::Env => "env",
            TokenSource::Keyring => "keyring",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedToken {
    pub token: String,
    pub source: TokenSource,
}

/// Resolve a token by walking the precedence chain: env → keyring → error.
/// Keyring backend errors (no daemon, denied access) fall through to the
/// next layer rather than surfacing as fatal — so a user with only an env
/// token isn't blocked by a missing Secret Service daemon.
pub fn resolve() -> Result<ResolvedToken> {
    if let Ok(t) = std::env::var(TOKEN_ENV) {
        if !t.is_empty() {
            return Ok(ResolvedToken {
                token: t,
                source: TokenSource::Env,
            });
        }
    }
    if let Some(t) = read_keyring() {
        return Ok(ResolvedToken {
            token: t,
            source: TokenSource::Keyring,
        });
    }
    Err(SidestepError::Auth(format!(
        "no token found. Set {TOKEN_ENV}=<bearer-token>, or run \
         `sidestep auth login --token <bearer-token>` to store one in \
         the platform keyring. (Config file fallback is a future option \
         — charter F4.)"
    )))
}

/// Backwards-compatible single-string return; prefer `resolve` so the
/// caller can record `TokenSource` in audit metadata.
pub fn resolve_token() -> Result<String> {
    resolve().map(|r| r.token)
}

/// Read the token from the platform keyring. Returns `None` for both
/// "no entry" and "backend unavailable" — both mean "fall through."
pub fn read_keyring() -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).ok()?;
    entry.get_password().ok()
}

/// Store a token in the platform keyring, replacing any existing entry.
pub fn store_keyring(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(SidestepError::Auth("token must not be empty".into()));
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| SidestepError::Auth(format!("keyring open: {e}")))?;
    entry
        .set_password(token)
        .map_err(|e| SidestepError::Auth(format!("keyring write: {e}")))?;
    Ok(())
}

/// Delete the keyring entry. Returns `Ok(false)` if there was nothing to
/// delete — that is not an error.
pub fn delete_keyring() -> Result<bool> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| SidestepError::Auth(format!("keyring open: {e}")))?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(SidestepError::Auth(format!("keyring delete: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_source_as_str_is_stable() {
        assert_eq!(TokenSource::Env.as_str(), "env");
        assert_eq!(TokenSource::Keyring.as_str(), "keyring");
    }
}
