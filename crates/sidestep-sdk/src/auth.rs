//! Token resolution. Resolves env → keyring → config file → error.
//! Closes charter F4.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SidestepError};

pub const TOKEN_ENV: &str = "SIDESTEP_API_TOKEN";
pub const CONFIG_ENV: &str = "SIDESTEP_CONFIG";
pub const KEYRING_SERVICE: &str = "sidestep";
pub const KEYRING_USER: &str = "default";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSource {
    Env,
    Keyring,
    Config,
}

impl TokenSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenSource::Env => "env",
            TokenSource::Keyring => "keyring",
            TokenSource::Config => "config",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedToken {
    pub token: String,
    pub source: TokenSource,
}

/// Resolve a token by walking the precedence chain:
/// env → keyring → config file → error.
///
/// Keyring backend errors (no daemon, denied access) fall through to the
/// next layer rather than surfacing as fatal — so a user with only env
/// or only a config file isn't blocked by a missing Secret Service.
/// A malformed config file IS fatal: silent failure here would mask a
/// real auth misconfiguration.
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
    if let Some(t) = read_config_token()? {
        return Ok(ResolvedToken {
            token: t,
            source: TokenSource::Config,
        });
    }
    Err(SidestepError::Auth(format!(
        "no token found. Set {TOKEN_ENV}=<bearer-token>, run \
         `sidestep auth login --token <bearer-token>` to store one in \
         the platform keyring, or write `[auth] token = \"<value>\"` \
         to {}.",
        config_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/sidestep/config.toml".into())
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

/// Configuration loaded from `~/.config/sidestep/config.toml` (or the
/// path in `SIDESTEP_CONFIG`). Only `[auth]` is consumed in v0.1; the
/// struct is `#[serde(default)]` so future sections can be added
/// without breaking parsing.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub auth: AuthConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub token: Option<String>,
}

/// Resolve the config file path. `SIDESTEP_CONFIG` overrides; otherwise
/// the XDG config dir + `sidestep/config.toml` is used. Returns `None`
/// only when neither override nor a home directory is discoverable.
pub fn config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var(CONFIG_ENV) {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    dirs::config_dir().map(|d| d.join("sidestep").join("config.toml"))
}

/// Read the token from the config file. Returns:
///   * `Ok(Some(token))` — file present, parsed, token non-empty
///   * `Ok(None)`        — file absent, or present but no `[auth].token`
///   * `Err(...)`        — file present but malformed (TOML parse failed)
pub fn read_config_token() -> Result<Option<String>> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    let body = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(SidestepError::Auth(format!(
                "read config {}: {e}",
                path.display()
            )));
        }
    };
    let parsed: Config = toml::from_str(&body)
        .map_err(|e| SidestepError::Auth(format!("parse config {}: {e}", path.display())))?;
    Ok(parsed.auth.token.filter(|t| !t.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_source_as_str_is_stable() {
        assert_eq!(TokenSource::Env.as_str(), "env");
        assert_eq!(TokenSource::Keyring.as_str(), "keyring");
        assert_eq!(TokenSource::Config.as_str(), "config");
    }

    #[test]
    fn parse_full_config() {
        let body = r#"
[auth]
token = "abc123"
"#;
        let cfg: Config = toml::from_str(body).expect("parse");
        assert_eq!(cfg.auth.token.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_empty_config() {
        let cfg: Config = toml::from_str("").expect("parse");
        assert_eq!(cfg.auth.token, None);
    }

    #[test]
    fn parse_unrelated_sections_ok() {
        // Future sections must not break auth parsing.
        let body = r#"
[future_section]
flag = true

[auth]
token = "xyz"
"#;
        let cfg: Config = toml::from_str(body).expect("parse");
        assert_eq!(cfg.auth.token.as_deref(), Some("xyz"));
    }

    #[test]
    fn parse_malformed_errors() {
        let body = "this is = not = toml";
        let result: std::result::Result<Config, _> = toml::from_str(body);
        assert!(result.is_err());
    }
}
