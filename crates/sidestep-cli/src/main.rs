//! sidestep — Rust CLI for the StepSecurity API.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use serde_json::{Map, Value};
use sidestep_sdk::{CallOptions, Client, registry};

#[derive(Parser, Debug)]
#[command(
    name = "sidestep",
    version,
    about = "Rust CLI for the StepSecurity API",
    long_about = "Agent-first CLI over the StepSecurity API. Codegen from OpenAPI, audit-trail-as-feature.\n\nSet SIDESTEP_API_TOKEN to authenticate. Use `sidestep ops list` to discover operations and `sidestep api <operationId> --param k=v` to invoke any of them."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Invoke any operation in the OpenAPI spec by ID.
    Api(ApiArgs),
    /// List operations in the spec.
    Ops(OpsArgs),
}

#[derive(clap::Args, Debug)]
#[command(
    long_about = "Invoke any operation in the StepSecurity OpenAPI spec by its operationId.\n\n\
                  Path and query parameters are supplied as repeatable --param k=v.\n\
                  Request bodies (POST/PUT/PATCH) are passed as --body '{...json...}'.\n\n\
                  Examples:\n  \
                  sidestep api listWorkflowRuns --param owner=arcaven\n  \
                  sidestep api getWorkflowRun --param owner=arcaven --param repo=sidestep --param runid=42"
)]
struct ApiArgs {
    /// operationId from the OpenAPI spec. Run `sidestep ops list` to discover.
    operation_id: String,

    /// Path or query parameter as `key=value`. Repeatable.
    #[arg(long = "param", short = 'p', value_name = "KEY=VALUE")]
    params: Vec<String>,

    /// Request body as JSON. For POST/PUT/PATCH operations.
    #[arg(long, value_name = "JSON")]
    body: Option<String>,

    /// Skip operation/response detail in the audit trail (still records a stub).
    #[arg(long)]
    no_audit: bool,
}

#[derive(clap::Args, Debug)]
struct OpsArgs {
    #[command(subcommand)]
    cmd: OpsCmd,
}

#[derive(Subcommand, Debug)]
enum OpsCmd {
    /// List operationIds in the vendored spec.
    List {
        /// Substring filter on the operationId.
        #[arg(long)]
        filter: Option<String>,
    },
    /// Show details for one operation.
    Show {
        /// operationId from the OpenAPI spec.
        operation_id: String,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let cmd = match cli.cmd {
        Some(c) => c,
        None => {
            println!(
                "sidestep {}\n\nUse `sidestep --help` for usage.",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
    };

    let result = match cmd {
        Cmd::Api(args) => run_api(args),
        Cmd::Ops(args) => run_ops(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sidestep: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_ops(args: OpsArgs) -> anyhow::Result<()> {
    match args.cmd {
        OpsCmd::List { filter } => {
            let mut ids: Vec<&str> = registry()
                .iter()
                .map(|m| m.id.as_str())
                .filter(|id| match &filter {
                    Some(needle) => id.to_lowercase().contains(&needle.to_lowercase()),
                    None => true,
                })
                .collect();
            ids.sort_unstable();
            for id in ids {
                println!("{id}");
            }
            Ok(())
        }
        OpsCmd::Show { operation_id } => {
            let r = registry();
            let op = r.find(&operation_id).map_err(|e| anyhow!("{e}"))?;
            let summary = op.summary.as_deref().unwrap_or("");
            println!("operationId: {}", op.id);
            println!("method:      {}", op.method.as_str());
            println!("path:        {}{}", r.base_url, op.path_template);
            if !summary.is_empty() {
                println!("summary:     {summary}");
            }
            if !op.path_params.is_empty() {
                println!("path params:");
                for p in &op.path_params {
                    let req = if op.required_params.contains(p) {
                        " (required)"
                    } else {
                        ""
                    };
                    println!("  - {p}{req}");
                }
            }
            if !op.query_params.is_empty() {
                println!("query params:");
                for p in &op.query_params {
                    let req = if op.required_params.contains(p) {
                        " (required)"
                    } else {
                        ""
                    };
                    println!("  - {p}{req}");
                }
            }
            if op.has_body {
                println!("body:        required (pass --body '<json>')");
            }
            Ok(())
        }
    }
}

fn run_api(args: ApiArgs) -> anyhow::Result<()> {
    let mut params = parse_params(&args.params)?;
    if let Some(body) = args.body {
        let body_value: Value = serde_json::from_str(&body).context("--body must be valid JSON")?;
        params.insert("body".to_string(), body_value);
    }
    let params_value = Value::Object(params);

    let client = Client::from_env().map_err(|e| anyhow!("{e}"))?;
    let opts = CallOptions {
        no_audit: args.no_audit,
        ..Default::default()
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let response = runtime
        .block_on(client.call_op(&args.operation_id, &params_value, opts))
        .map_err(|e| anyhow!("{e}"))?;

    let pretty = serde_json::to_string_pretty(&response).context("serialize response as JSON")?;
    println!("{pretty}");
    Ok(())
}

fn parse_params(raw: &[String]) -> anyhow::Result<Map<String, Value>> {
    let mut out = Map::new();
    for entry in raw {
        let (k, v) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("--param expects `key=value`, got `{entry}`"))?;
        // Try to parse the value as JSON first (lets users pass numbers, bools,
        // arrays without quoting). Fall back to plain string.
        let value = serde_json::from_str(v).unwrap_or(Value::String(v.to_string()));
        out.insert(k.to_string(), value);
    }
    Ok(out)
}
