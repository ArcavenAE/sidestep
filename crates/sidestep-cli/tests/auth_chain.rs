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
