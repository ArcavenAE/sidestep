//! Token resolution and per-param resolution chains.
//!
//! Two chains live here, both instantiations of the
//! `val-resolution-chain` bedrock pattern (see sidestep/charter.md B5):
//!
//! * **Token chain** — env → keyring → config file → error.
//! * **Param chain** — flag → env → config file → none. Used for
//!   near-constant path parameters (`owner`, `customer`) that would
//!   otherwise satisfy the abusive-argument test
//!   (`.claude/rules/cli-philosophy.md`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Result, SidestepError};

pub const TOKEN_ENV: &str = "SIDESTEP_API_TOKEN";
pub const OWNER_ENV: &str = "SIDESTEP_OWNER";
pub const CUSTOMER_ENV: &str = "SIDESTEP_CUSTOMER";
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

/// Source of a path-parameter resolution. Mirrors `TokenSource` but
/// drops `Keyring` (path params aren't secrets) and adds a `Flag`
/// variant for explicit per-call overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParamSource {
    Flag,
    Env,
    Config,
}

impl ParamSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ParamSource::Flag => "flag",
            ParamSource::Env => "env",
            ParamSource::Config => "config",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedToken {
    pub token: String,
    pub source: TokenSource,
}

#[derive(Clone, Debug)]
pub struct ResolvedParam {
    pub value: String,
    pub source: ParamSource,
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

/// Resolve `owner` by walking flag → env (`SIDESTEP_OWNER`) →
/// config (`[default] owner`). Returns `Ok(None)` when no source
/// supplies a value — the caller decides whether the underlying
/// operation actually requires `{owner}` and raises a missing-param
/// error naming the chain.
pub fn resolve_owner(flag: Option<&str>) -> Result<Option<ResolvedParam>> {
    resolve_param(flag, OWNER_ENV, |c| c.default.owner.clone())
}

/// Resolve `customer` by walking flag → env (`SIDESTEP_CUSTOMER`) →
/// config (`[default] customer`). Returns `Ok(None)` when no source
/// supplies a value.
pub fn resolve_customer(flag: Option<&str>) -> Result<Option<ResolvedParam>> {
    resolve_param(flag, CUSTOMER_ENV, |c| c.default.customer.clone())
}

fn resolve_param(
    flag: Option<&str>,
    env_var: &str,
    from_config: impl FnOnce(&Config) -> Option<String>,
) -> Result<Option<ResolvedParam>> {
    if let Some(v) = flag {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Ok(Some(ResolvedParam {
                value: trimmed.to_string(),
                source: ParamSource::Flag,
            }));
        }
    }
    if let Ok(v) = std::env::var(env_var) {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Ok(Some(ResolvedParam {
                value: trimmed.to_string(),
                source: ParamSource::Env,
            }));
        }
    }
    if let Some(cfg) = read_config()? {
        if let Some(v) = from_config(&cfg) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Ok(Some(ResolvedParam {
                    value: trimmed.to_string(),
                    source: ParamSource::Config,
                }));
            }
        }
    }
    Ok(None)
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
/// path in `SIDESTEP_CONFIG`). The struct is `#[serde(default)]` so
/// future sections can be added without breaking parsing.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    #[serde(skip_serializing_if = "AuthConfig::is_empty")]
    pub auth: AuthConfig,
    #[serde(skip_serializing_if = "DefaultConfig::is_empty")]
    pub default: DefaultConfig,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AuthConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl AuthConfig {
    fn is_empty(&self) -> bool {
        self.token.is_none()
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DefaultConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
}

impl DefaultConfig {
    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.customer.is_none()
    }
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

/// Read and parse the config file. Returns:
///   * `Ok(Some(cfg))` — file present, parsed
///   * `Ok(None)`      — file absent, or no discoverable config path
///   * `Err(...)`      — file present but malformed (TOML parse failed)
pub fn read_config() -> Result<Option<Config>> {
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
    Ok(Some(parsed))
}

/// Read the token from the config file. Returns:
///   * `Ok(Some(token))` — file present, parsed, token non-empty
///   * `Ok(None)`        — file absent, or present but no `[auth].token`
///   * `Err(...)`        — file present but malformed (TOML parse failed)
pub fn read_config_token() -> Result<Option<String>> {
    Ok(read_config()?.and_then(|c| c.auth.token.filter(|t| !t.is_empty())))
}

/// Read-merge-write the config file. Loads the existing config (or a
/// fresh default), applies `mutate`, then writes the result to disk —
/// preserving every section the caller did not touch. Creates the
/// parent directory if missing. Returns the path that was written.
pub fn write_config(mutate: impl FnOnce(&mut Config)) -> Result<PathBuf> {
    let path =
        config_path().ok_or_else(|| SidestepError::Auth("no discoverable config path".into()))?;
    let mut cfg = read_config()?.unwrap_or_default();
    mutate(&mut cfg);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            SidestepError::Auth(format!("create config dir {}: {e}", parent.display()))
        })?;
    }
    let body = toml::to_string_pretty(&cfg)
        .map_err(|e| SidestepError::Auth(format!("serialize config: {e}")))?;
    std::fs::write(&path, body)
        .map_err(|e| SidestepError::Auth(format!("write config {}: {e}", path.display())))?;
    Ok(path)
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
    fn param_source_as_str_is_stable() {
        assert_eq!(ParamSource::Flag.as_str(), "flag");
        assert_eq!(ParamSource::Env.as_str(), "env");
        assert_eq!(ParamSource::Config.as_str(), "config");
    }

    #[test]
    fn parse_full_config() {
        let body = r#"
[auth]
token = "abc123"

[default]
owner = "arcaven"
customer = "1898andCo"
"#;
        let cfg: Config = toml::from_str(body).expect("parse");
        assert_eq!(cfg.auth.token.as_deref(), Some("abc123"));
        assert_eq!(cfg.default.owner.as_deref(), Some("arcaven"));
        assert_eq!(cfg.default.customer.as_deref(), Some("1898andCo"));
    }

    #[test]
    fn parse_empty_config() {
        let cfg: Config = toml::from_str("").expect("parse");
        assert_eq!(cfg.auth.token, None);
        assert_eq!(cfg.default.owner, None);
        assert_eq!(cfg.default.customer, None);
    }

    #[test]
    fn parse_unrelated_sections_ok() {
        // Future sections must not break parsing of known sections.
        let body = r#"
[future_section]
flag = true

[auth]
token = "xyz"

[default]
owner = "arcaven"
"#;
        let cfg: Config = toml::from_str(body).expect("parse");
        assert_eq!(cfg.auth.token.as_deref(), Some("xyz"));
        assert_eq!(cfg.default.owner.as_deref(), Some("arcaven"));
    }

    #[test]
    fn parse_default_only_no_auth() {
        let body = r#"
[default]
owner = "arcaven"
"#;
        let cfg: Config = toml::from_str(body).expect("parse");
        assert_eq!(cfg.auth.token, None);
        assert_eq!(cfg.default.owner.as_deref(), Some("arcaven"));
    }

    #[test]
    fn parse_malformed_errors() {
        let body = "this is = not = toml";
        let result: std::result::Result<Config, _> = toml::from_str(body);
        assert!(result.is_err());
    }

    #[test]
    fn serialize_skips_empty_sections() {
        let cfg = Config::default();
        let body = toml::to_string_pretty(&cfg).expect("serialize");
        // Empty config writes nothing — both sections are skipped.
        assert!(
            !body.contains("[auth]"),
            "empty auth section should be skipped: {body:?}"
        );
        assert!(
            !body.contains("[default]"),
            "empty default section should be skipped: {body:?}"
        );
    }

    #[test]
    fn serialize_round_trip_default_only() {
        let mut cfg = Config::default();
        cfg.default.owner = Some("arcaven".into());
        let body = toml::to_string_pretty(&cfg).expect("serialize");
        assert!(body.contains("[default]"), "want [default] in {body:?}");
        assert!(
            body.contains("owner = \"arcaven\""),
            "want owner in {body:?}"
        );
        assert!(
            !body.contains("[auth]"),
            "empty auth section should be skipped: {body:?}"
        );
    }
}
