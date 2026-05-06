//! End-to-end coverage for `auth login --owner/--customer`,
//! `auth status` reporting, and the `config` subcommand. Uses a
//! per-test tempdir + `SIDESTEP_CONFIG` so the user's real config is
//! never touched.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use assert_cmd::cargo::CommandCargoExt;

static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn tempdir() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = TEMPDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("sidestep-auth-{}-{n}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cmd() -> Command {
    Command::cargo_bin("sidestep").expect("sidestep")
}

#[test]
fn auth_login_with_no_source_errors_naming_the_chain() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");

    let out = cmd()
        .args(["auth", "login"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!out.status.success(), "expected failure: {out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--token") && err.contains("--owner") && err.contains("--customer"),
        "error must name the resolution chain: {err}"
    );
    assert!(!cfg.exists(), "config should not be created on error");
}

#[test]
fn auth_login_owner_persists_to_config_without_token() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");

    let out = cmd()
        .args(["auth", "login", "--owner", "arcaven"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .output()
        .unwrap();

    assert!(out.status.success(), "auth login --owner failed: {out:?}");
    let body = std::fs::read_to_string(&cfg).expect("config written");
    assert!(
        body.contains("owner = \"arcaven\""),
        "config must persist owner: {body}"
    );
    assert!(
        body.contains("[default]"),
        "config must carry [default] section: {body}"
    );
    assert!(
        !body.contains("[auth]"),
        "no token supplied — [auth] section should not be written: {body}"
    );
}

#[test]
fn auth_login_owner_and_customer_together() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");

    let out = cmd()
        .args([
            "auth",
            "login",
            "--owner",
            "arcaven",
            "--customer",
            "1898andCo",
        ])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    let body = std::fs::read_to_string(&cfg).unwrap();
    assert!(body.contains("owner = \"arcaven\""), "{body}");
    assert!(body.contains("customer = \"1898andCo\""), "{body}");
}

#[test]
fn auth_login_owner_does_not_clobber_existing_token_or_customer() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        r#"
[auth]
token = "preexisting-token"

[default]
customer = "1898andCo"
"#,
    )
    .unwrap();

    let out = cmd()
        .args(["auth", "login", "--owner", "arcaven"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");

    let body = std::fs::read_to_string(&cfg).unwrap();
    assert!(
        body.contains("token = \"preexisting-token\""),
        "token must be preserved: {body}"
    );
    assert!(
        body.contains("customer = \"1898andCo\""),
        "customer must be preserved: {body}"
    );
    assert!(
        body.contains("owner = \"arcaven\""),
        "owner must be added: {body}"
    );
}

#[test]
fn auth_status_reports_owner_source_from_env() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");

    let out = cmd()
        .args(["auth", "status"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env("SIDESTEP_API_TOKEN", "fake-token")
        .env("SIDESTEP_OWNER", "from-env")
        .env_remove("SIDESTEP_CUSTOMER")
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("owner:    from-env (source: env)"),
        "owner-from-env not reported: {stdout}"
    );
    assert!(
        stdout.contains("customer: unset"),
        "customer should be unset: {stdout}"
    );
}

#[test]
fn auth_status_reports_owner_source_from_config_when_env_absent() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        r#"
[default]
owner = "from-config"
"#,
    )
    .unwrap();

    let out = cmd()
        .args(["auth", "status"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env("SIDESTEP_API_TOKEN", "fake-token")
        .env_remove("SIDESTEP_OWNER")
        .env_remove("SIDESTEP_CUSTOMER")
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("owner:    from-config (source: config)"),
        "config-source not reported: {stdout}"
    );
}

#[test]
fn auth_status_env_beats_config() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        r#"
[default]
owner = "from-config"
"#,
    )
    .unwrap();

    let out = cmd()
        .args(["auth", "status"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env("SIDESTEP_API_TOKEN", "fake-token")
        .env("SIDESTEP_OWNER", "from-env")
        .env_remove("SIDESTEP_CUSTOMER")
        .output()
        .unwrap();

    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("owner:    from-env (source: env)"),
        "env should win over config: {stdout}"
    );
}

#[test]
fn config_show_redacts_token_length() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        r#"
[auth]
token = "abcdef"

[default]
owner = "arcaven"
"#,
    )
    .unwrap();

    let out = cmd()
        .args(["config", "show"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("<redacted, length=6>"),
        "token must be redacted: {stdout}"
    );
    assert!(!stdout.contains("abcdef"), "raw token leaked: {stdout}");
    assert!(stdout.contains("owner = \"arcaven\""), "{stdout}");
}

#[test]
fn config_set_then_unset_owner_round_trip() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");

    let out = cmd()
        .args(["config", "set", "owner", "arcaven"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .output()
        .unwrap();
    assert!(out.status.success(), "set failed: {out:?}");
    let body = std::fs::read_to_string(&cfg).unwrap();
    assert!(body.contains("owner = \"arcaven\""), "{body}");

    let out = cmd()
        .args(["config", "unset", "owner"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .output()
        .unwrap();
    assert!(out.status.success(), "unset failed: {out:?}");
    let body = std::fs::read_to_string(&cfg).unwrap();
    assert!(!body.contains("owner ="), "owner not cleared: {body}");
}

#[test]
fn config_set_unknown_key_errors_with_known_keys_listed() {
    let dir = tempdir();
    let cfg = dir.join("config.toml");

    let out = cmd()
        .args(["config", "set", "bogus", "value"])
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_API_TOKEN")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("owner"), "{err}");
    assert!(err.contains("customer"), "{err}");
    assert!(err.contains("auth.token"), "{err}");
}

#[test]
fn list_without_owner_errors_with_chain_naming_message() {
    // The aae-orc-1mgo / cli-philosophy.md "The fix" rule: when a
    // chain-tracked path param is required but unresolved, the error
    // names every layer of the chain plus a concrete next step for
    // each. Bare "missing required parameter 'owner'" is the bad shape
    // we replaced.
    let dir = tempdir();
    let cfg = dir.join("nonexistent.toml");

    let out = cmd()
        .args(["list", "rule"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_OWNER")
        .env_remove("SIDESTEP_CUSTOMER")
        .output()
        .unwrap();

    assert!(!out.status.success(), "expected failure: {out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no owner resolved"),
        "should name what's missing: {err}"
    );
    // Every layer of the chain must be reachable from the message.
    assert!(err.contains("--owner"), "missing flag layer: {err}");
    assert!(err.contains("SIDESTEP_OWNER"), "missing env layer: {err}");
    assert!(
        err.contains("sidestep auth login --owner"),
        "missing auth-login persistence layer: {err}"
    );
    assert!(
        err.contains("sidestep config set owner"),
        "missing config-set persistence layer: {err}"
    );
    // The bare SDK error should NOT leak through any more.
    assert!(
        !err.contains("missing required parameter"),
        "SDK MissingParam leaked through, CLI guard didn't fire first: {err}"
    );
}

#[test]
fn list_audit_log_without_customer_errors_with_chain_naming_message() {
    // audit_log uses get_customer_audit_logs which has {customer} as
    // its only path param (owner is a query filter). Verify the
    // chain-naming guard fires for customer too, not just owner.
    let dir = tempdir();
    let cfg = dir.join("nonexistent.toml");

    let out = cmd()
        .args(["list", "audit_log"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_CONFIG", &cfg)
        .env_remove("SIDESTEP_OWNER")
        .env_remove("SIDESTEP_CUSTOMER")
        .output()
        .unwrap();

    assert!(!out.status.success(), "expected failure: {out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("no customer resolved"),
        "should name customer specifically: {err}"
    );
    assert!(err.contains("--customer"), "{err}");
    assert!(err.contains("SIDESTEP_CUSTOMER"), "{err}");
    assert!(err.contains("sidestep auth login --customer"), "{err}");
    assert!(err.contains("sidestep config set customer"), "{err}");
}

#[test]
fn list_with_owner_flag_skips_chain_error() {
    // Sanity: providing the flag short-circuits the chain check; we
    // fall through to whatever happens next (here, network failure
    // to a closed port). Chain message must NOT appear.
    let out = cmd()
        .args(["list", "rule", "--owner", "arcaven"])
        .env("SIDESTEP_API_TOKEN", "fake-tok")
        .env("SIDESTEP_BASE_URL", "http://127.0.0.1:1")
        .env_remove("SIDESTEP_OWNER")
        .env_remove("SIDESTEP_CUSTOMER")
        .env_remove("SIDESTEP_CONFIG")
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "expected network failure (port 1 is closed): {out:?}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("no owner resolved"),
        "chain error must not fire when --owner is provided: {err}"
    );
}
