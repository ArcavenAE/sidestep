//! sidestep — Rust CLI for the StepSecurity API.

#![forbid(unsafe_code)]

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "sidestep",
    version,
    about = "Rust CLI for the StepSecurity API",
    long_about = "Agent-first CLI over the StepSecurity API. Codegen from OpenAPI, audit-trail-as-feature.\n\nSee `sidestep <subcommand> --help` for per-resource verbs (forthcoming)."
)]
struct Cli;

fn main() -> anyhow::Result<()> {
    let _ = Cli::parse();
    println!(
        "sidestep {} — scaffold. Curated verbs and `sidestep api` not yet wired.",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}
