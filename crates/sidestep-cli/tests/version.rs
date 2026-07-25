//! `--version` build-identity smoke tests (aae-orc-c714).

use assert_cmd::Command;

#[test]
fn version_carries_build_id() {
    let out = Command::cargo_bin("sidestep")
        .expect("sidestep")
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    // "<name> <semver> (<build-id>)" — build id is parenthesized and
    // non-empty. Test builds have no SIDESTEP_BUILD_ID env, so the
    // stamp is the git fallback (`dev+g<sha7>[-dirty]`) or `unknown`.
    assert_eq!(text.trim().split(' ').next(), Some("sidestep"));
    assert!(
        text.contains(&format!("({})", sidestep_sdk::BUILD_ID)),
        "version output missing build id: {text:?}"
    );
    assert!(!sidestep_sdk::BUILD_ID.is_empty());
}
