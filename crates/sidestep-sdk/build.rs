//! Stamps a build identity into the SDK (surfaced by the CLI's
//! `--version` and the audit trail's `invocation.build_id`).
//!
//! Resolution order:
//! 1. `SIDESTEP_BUILD_ID` env — set by CI to the channel tag computed
//!    before the build (`alpha-…`, `v0.1.0-rc.N+g<sha7>`, `v0.1.0+g<sha7>`).
//! 2. Local git — `dev+g<sha7>[-dirty]`.
//! 3. `unknown` — no env, no `.git` (e.g. a source-tarball build).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SIDESTEP_BUILD_ID");
    // Best-effort: re-stamp local builds when HEAD moves. Harmless if
    // the path doesn't exist (cargo ignores missing rerun paths).
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let build_id = std::env::var("SIDESTEP_BUILD_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(local_git_id);
    println!("cargo:rustc-env=SIDESTEP_BUILD_ID={build_id}");
}

fn local_git_id() -> String {
    let sha = git(&["rev-parse", "--short=7", "HEAD"]);
    match sha {
        Some(sha) => {
            let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
            if dirty {
                format!("dev+g{sha}-dirty")
            } else {
                format!("dev+g{sha}")
            }
        }
        None => "unknown".to_string(),
    }
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}
