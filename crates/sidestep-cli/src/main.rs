//! sidestep — Rust CLI for the StepSecurity API.

#![forbid(unsafe_code)]

use std::io::{BufReader, IsTerminal, Read, Write};
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value};
use sidestep_sdk::{
    CallOptions, Client, Record, SourceRef, auth, cel, kind_spec, kinds, read_stream, registry,
    write_record,
};

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
    /// Manage stored credentials.
    Auth(AuthArgs),
    /// List records of a `_kind` from the API as a JSON-line stream.
    List(ListArgs),
    /// Format a JSON-line stream from stdin.
    Emit(EmitArgs),
    /// Drop records that don't match a CEL predicate.
    Filter(FilterArgs),
}

#[derive(clap::Args, Debug)]
#[command(long_about = "Manage credentials for sidestep.\n\n\
                  sidestep resolves tokens in this order:\n  \
                  1. SIDESTEP_API_TOKEN environment variable\n  \
                  2. Platform keyring (macOS Keychain, Linux Secret Service)\n  \
                  3. Config file at ~/.config/sidestep/config.toml \
                     (override with SIDESTEP_CONFIG)\n     \
                     [auth] token = \"<value>\"\n\n\
                  Use `sidestep auth login` to store a token in the keyring.")]
struct AuthArgs {
    #[command(subcommand)]
    cmd: AuthCmd,
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// Store a bearer token in the platform keyring.
    Login(AuthLoginArgs),
    /// Show whether a token is configured and where it came from.
    Status,
    /// Remove the token from the platform keyring.
    Logout,
}

#[derive(clap::Args, Debug)]
#[command(
    long_about = "Store a StepSecurity API bearer token in the platform keyring.\n\n\
                  Sources, in priority order:\n  \
                  --token <value>      explicit, useful for scripts\n  \
                  --stdin              read whole stdin (so `echo $T | sidestep auth login --stdin`)\n\n\
                  At least one source must be provided. Interactive prompting is not supported in v0.1.\n\
                  An existing keyring entry is overwritten without prompt."
)]
struct AuthLoginArgs {
    /// Bearer token. Redacted from the audit-trail argv.
    #[arg(long, value_name = "VALUE")]
    token: Option<String>,

    /// Read the token from stdin (entire stream, trimmed).
    #[arg(long, conflicts_with = "token")]
    stdin: bool,
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
#[command(
    long_about = "Stream records of a `_kind` from the StepSecurity API as JSON-lines.\n\n\
                  Each line carries `_kind` and `_source` (operation_id, response_index, \
                  fetched_at) plus the domain fields from the API response. Compose with \
                  `sidestep filter`, `sidestep enrich`, `sidestep emit`.\n\n\
                  Most kinds require `--owner <slug>` (the GitHub org or user). Other path \
                  / query parameters can be supplied via repeatable `--param k=v`.\n\n\
                  Examples:\n  \
                  sidestep list detections --owner arcaven\n  \
                  sidestep list policies --owner arcaven | sidestep emit --format md"
)]
struct ListArgs {
    /// Stream-contract `_kind`. Run `sidestep list --help` to see the v0.1 set.
    #[arg(value_parser = kind_value_parser())]
    kind: String,

    /// Convenience for the near-universal `owner` path parameter.
    #[arg(long)]
    owner: Option<String>,

    /// Path or query parameter as `key=value`. Repeatable. Use this for
    /// any parameter beyond `--owner`.
    #[arg(long = "param", short = 'p', value_name = "KEY=VALUE")]
    params: Vec<String>,

    /// Skip the per-call audit detail (still emits a stub).
    #[arg(long)]
    no_audit: bool,
}

#[derive(clap::Args, Debug)]
#[command(long_about = "Format a JSON-line stream from stdin.\n\n\
                  Records must follow the sidestep stream contract (`_kind`, `_source`, \
                  domain fields). Default output: `jsonl` (passthrough) for non-TTY, \
                  `md` markdown table for TTY.\n\n\
                  Formats:\n  \
                  jsonl   one record per line, exact passthrough\n  \
                  md      markdown table (kind, id, severity, primary timestamp)\n\n\
                  More formats (table, csv, sarif) ship in v0.2.")]
struct EmitArgs {
    /// Output format. If unset, defaults to `jsonl` (non-TTY) or `md` (TTY).
    #[arg(long, value_enum)]
    format: Option<EmitFormat>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum EmitFormat {
    Jsonl,
    Md,
}

#[derive(clap::Args, Debug)]
#[command(long_about = "Drop records that don't match a CEL predicate.\n\n\
                  The predicate is Common Expression Language (CEL). Each top-level field \
                  of a record is bound as a top-level variable, so you can write \
                  `severity == \"high\" && status == \"open\"` directly. The full record \
                  is also available as `record` for use with the `has()` macro \
                  (`has(record.suppressed_by)`).\n\n\
                  Adapter rules (per finding-001):\n  \
                  - `*_at` and `ts` fields are promoted to timestamps so `created_at < now` works\n  \
                  - missing top-level field access raises a runtime error (use `has(record.X)` instead)\n  \
                  - `now` is bound to the current UTC time per query\n  \
                  - the predicate must return a boolean\n\n\
                  Use `--explain` to print the schema, parsed AST, and `now` binding without \
                  consuming any records.\n\n\
                  Examples:\n  \
                  sidestep filter --where '_kind == \"detection\" && status == \"open\"'\n  \
                  sidestep filter --where 'severity in [\"critical\",\"high\"]'\n  \
                  sidestep filter --where 'created_at < now - duration(\"24h\")'\n  \
                  sidestep filter --where 'has(record.suppressed_by)' --explain")]
struct FilterArgs {
    /// CEL predicate. Returns one record per matching input.
    #[arg(long, value_name = "CEL")]
    r#where: String,

    /// Print the schema, parsed AST, and `now` binding, then exit
    /// without consuming stdin.
    #[arg(long)]
    explain: bool,
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
        Cmd::Auth(args) => run_auth(args),
        Cmd::List(args) => run_list(args),
        Cmd::Emit(args) => run_emit(args),
        Cmd::Filter(args) => run_filter(args),
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

fn run_auth(args: AuthArgs) -> anyhow::Result<()> {
    match args.cmd {
        AuthCmd::Login(login) => auth_login(login),
        AuthCmd::Status => auth_status(),
        AuthCmd::Logout => auth_logout(),
    }
}

fn auth_login(args: AuthLoginArgs) -> anyhow::Result<()> {
    let token = if let Some(t) = args.token {
        t
    } else if args.stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read --stdin")?;
        buf
    } else {
        return Err(anyhow!(
            "no token source. Pass `--token <value>` or `--stdin`. \
             See `sidestep auth login --help`."
        ));
    };
    let token = token.trim();
    if token.is_empty() {
        return Err(anyhow!("token must not be empty"));
    }
    auth::store_keyring(token).map_err(|e| anyhow!("{e}"))?;
    let target = match auth::read_keyring() {
        Some(_) => "stored in keyring",
        None => "stored — but immediate read-back failed (keyring backend may be unavailable)",
    };
    eprintln!("sidestep auth: {target}");
    Ok(())
}

fn auth_status() -> anyhow::Result<()> {
    match auth::resolve() {
        Ok(resolved) => {
            // Never print the token. Length + source is the contract.
            println!(
                "authenticated\n  source: {}\n  length: {} bytes",
                resolved.source.as_str(),
                resolved.token.len()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("not authenticated: {e}");
            std::process::exit(1);
        }
    }
}

fn auth_logout() -> anyhow::Result<()> {
    let removed = auth::delete_keyring().map_err(|e| anyhow!("{e}"))?;
    if removed {
        eprintln!("sidestep auth: keyring entry removed");
    } else {
        eprintln!("sidestep auth: no keyring entry to remove");
    }
    Ok(())
}

fn run_list(args: ListArgs) -> anyhow::Result<()> {
    let spec = kind_spec(&args.kind).ok_or_else(|| {
        anyhow!(
            "unknown kind '{}' — run with --help to see the v0.1 set",
            args.kind
        )
    })?;
    let op_id = spec.list_operation_id.ok_or_else(|| {
        anyhow!(
            "kind '{}' has no list endpoint in the v0.1 spec — derive it from another kind via `enrich`",
            spec.name
        )
    })?;

    let mut params = parse_params(&args.params)?;
    if let Some(owner) = &args.owner {
        params.insert("owner".to_string(), Value::String(owner.clone()));
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
        .block_on(client.call_op(op_id, &params_value, opts))
        .map_err(|e| anyhow!("{e}"))?;

    let items_owned: Vec<Value> = match kinds::extract_items(&response) {
        Some(items) => items.to_vec(),
        None => {
            // Single-record responses (no array wrapper) are still valid —
            // surface the body as one record.
            vec![response]
        }
    };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for (idx, item) in items_owned.into_iter().enumerate() {
        let record = Record::wrap(spec.name, SourceRef::now(op_id, idx), item);
        write_record(&mut out, &record).map_err(|e| anyhow!("{e}"))?;
    }
    Ok(())
}

fn run_filter(args: FilterArgs) -> anyhow::Result<()> {
    let predicate = &args.r#where;
    let program = cel::compile(predicate).map_err(|e| anyhow!("{e}"))?;

    if args.explain {
        return explain_filter(predicate, &program);
    }

    let now = chrono_now();
    let stdin = std::io::stdin();
    let stdin = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for record in read_stream(stdin) {
        let record = record.map_err(|e| anyhow!("{e}"))?;
        let keep = cel::evaluate(&program, &record, now, predicate).map_err(|e| anyhow!("{e}"))?;
        if keep {
            write_record(&mut out, &record).map_err(|e| anyhow!("{e}"))?;
        }
    }
    Ok(())
}

fn explain_filter(predicate: &str, program: &cel_interpreter::Program) -> anyhow::Result<()> {
    let now = chrono_now();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "predicate: {predicate}")?;
    writeln!(out, "now:       {}", now.to_rfc3339())?;
    writeln!(out, "ast:       {program:#?}")?;
    writeln!(out)?;
    writeln!(out, "v0.1 kind schemas (for predicate authoring):")?;
    for spec in kinds::all_kinds() {
        writeln!(
            out,
            "  {:<14}  id={}  severity={}  ts={}",
            spec.name,
            spec.id_field,
            spec.severity_field.unwrap_or("-"),
            spec.primary_timestamp_field.unwrap_or("-"),
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Bindings per record: each top-level field becomes a CEL variable;"
    )?;
    writeln!(
        out,
        "the full record is also available as `record` for `has()` checks."
    )?;
    Ok(())
}

fn chrono_now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

fn run_emit(args: EmitArgs) -> anyhow::Result<()> {
    let format = args.format.unwrap_or_else(|| {
        if std::io::stdout().is_terminal() {
            EmitFormat::Md
        } else {
            EmitFormat::Jsonl
        }
    });

    let stdin = std::io::stdin();
    let stdin = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match format {
        EmitFormat::Jsonl => {
            for record in read_stream(stdin) {
                let record = record.map_err(|e| anyhow!("{e}"))?;
                write_record(&mut out, &record).map_err(|e| anyhow!("{e}"))?;
            }
        }
        EmitFormat::Md => {
            // Buffer so we can emit the header once and rows after.
            let records: Vec<Record> = read_stream(stdin)
                .collect::<sidestep_sdk::Result<Vec<_>>>()
                .map_err(|e| anyhow!("{e}"))?;
            emit_markdown_table(&mut out, &records)?;
        }
    }
    Ok(())
}

/// Render a small markdown table of a stream of records.
///
/// Columns: `_kind`, `id`, `severity`, primary timestamp. The id /
/// severity / timestamp field names come from `KindSpec`. Records of
/// unknown kinds use generic fallbacks (`id`, `severity`, no timestamp).
fn emit_markdown_table<W: Write>(out: &mut W, records: &[Record]) -> anyhow::Result<()> {
    writeln!(out, "| _kind | id | severity | timestamp |")?;
    writeln!(out, "|---|---|---|---|")?;
    for r in records {
        let spec = kind_spec(&r.kind);
        let id_field = spec.map(|s| s.id_field).unwrap_or("id");
        let sev_field = spec.and_then(|s| s.severity_field).unwrap_or("severity");
        let ts_field = spec.and_then(|s| s.primary_timestamp_field);

        let id = r.get(id_field).and_then(scalar).unwrap_or_default();
        let sev = r.get(sev_field).and_then(scalar).unwrap_or_default();
        let ts = ts_field
            .and_then(|f| r.get(f))
            .and_then(scalar)
            .unwrap_or_default();

        writeln!(out, "| {} | {} | {} | {} |", r.kind, id, sev, ts)?;
    }
    Ok(())
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        _ => Some(v.to_string()),
    }
}

fn kind_value_parser() -> clap::builder::PossibleValuesParser {
    clap::builder::PossibleValuesParser::new(kinds::ALL_KINDS)
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
