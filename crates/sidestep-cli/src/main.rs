//! sidestep — Rust CLI for the StepSecurity API.

#![forbid(unsafe_code)]

use std::io::{BufReader, IsTerminal, Read, Write};
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value};
use sidestep_sdk::{
    CallOptions, Client, Record, SourceRef, auth, cel, enrich, kind_spec, kinds, read_stream,
    registry, write_record,
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
    /// Fetch a single record by ID and emit one JSON line.
    Get(GetArgs),
    /// List + substring match against the kind's search field.
    Search(SearchArgs),
    /// Format a JSON-line stream from stdin.
    Emit(EmitArgs),
    /// Drop records that don't match a CEL predicate.
    Filter(FilterArgs),
    /// Attach computed/joined fields per a named recipe.
    Enrich(EnrichArgs),
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

    /// Convenience for the `repo` path parameter (used by some kinds).
    #[arg(long)]
    repo: Option<String>,

    /// Path or query parameter as `key=value`. Repeatable. Use this for
    /// any parameter beyond `--owner` and `--repo`.
    #[arg(long = "param", short = 'p', value_name = "KEY=VALUE")]
    params: Vec<String>,

    /// Maximum number of records to emit. Applies after `--since`.
    #[arg(long, value_name = "N")]
    limit: Option<usize>,

    /// Drop records older than this duration. Format follows Go's
    /// duration syntax (`24h`, `30m`, `1h30m`, `0.5h`). Valid units:
    /// `ns`, `us`, `µs`, `ms`, `s`, `m`, `h`. (Go duration does not
    /// accept `d` for days — use `24h`, `48h`, etc.) Requires the
    /// kind to have a primary timestamp field.
    #[arg(long, value_name = "DUR")]
    since: Option<String>,

    /// Skip the per-call audit detail (still emits a stub).
    #[arg(long)]
    no_audit: bool,
}

#[derive(clap::Args, Debug)]
#[command(long_about = "Fetch a single record by ID.\n\n\
                  Most kinds need additional path context — `--owner` and often `--repo` — \
                  to disambiguate. The `<id>` argument binds to the kind's id path parameter \
                  (`runid` for runs, `incidentId` for incidents, etc.).\n\n\
                  Examples:\n  \
                  sidestep get run a1b2c3 --owner arcaven --repo marvel\n  \
                  sidestep get incident inc_001 --owner arcaven")]
struct GetArgs {
    /// Stream-contract `_kind` (must have a get-by-id endpoint).
    #[arg(value_parser = kind_value_parser())]
    kind: String,

    /// Identifier for the record. Maps to the kind's id path param.
    id: String,

    /// `owner` path parameter (required by every v0.1 get endpoint).
    #[arg(long)]
    owner: Option<String>,

    /// `repo` path parameter (required by run + check).
    #[arg(long)]
    repo: Option<String>,

    /// Additional path / query parameters as `key=value`. Repeatable.
    #[arg(long = "param", short = 'p', value_name = "KEY=VALUE")]
    params: Vec<String>,

    /// Skip the per-call audit detail (still emits a stub).
    #[arg(long)]
    no_audit: bool,
}

#[derive(clap::Args, Debug)]
#[command(
    long_about = "Substring-match a `list` stream against the kind's search field.\n\n\
                  Implementation: list under the hood, then drop records whose \
                  `search_field` does not contain the query (case-insensitive). \
                  This is a v0.1 fallback — kinds without dedicated search endpoints \
                  use the kind-specific search field defined in the SDK kind table.\n\n\
                  Examples:\n  \
                  sidestep search policy egress --owner arcaven\n  \
                  sidestep search detection malware --owner arcaven --limit 5"
)]
struct SearchArgs {
    /// Stream-contract `_kind` (must define a search field).
    #[arg(value_parser = kind_value_parser())]
    kind: String,

    /// Substring to match (case-insensitive).
    query: String,

    /// `owner` path parameter for the underlying `list` call.
    #[arg(long)]
    owner: Option<String>,

    /// `repo` path parameter (used by some kinds).
    #[arg(long)]
    repo: Option<String>,

    /// Additional path / query parameters as `key=value`. Repeatable.
    #[arg(long = "param", short = 'p', value_name = "KEY=VALUE")]
    params: Vec<String>,

    /// Maximum number of matching records to emit.
    #[arg(long, value_name = "N")]
    limit: Option<usize>,

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
#[command(
    long_about = "Attach computed or joined fields to records per a named recipe.\n\n\
                  Recipes (v0.1):\n  \
                  policy-context     for each rule, attach parent policy as `policy: {...}`. \
                                     Orphans get `policy: null`. Other kinds pass through. \
                                     Requires --policies.\n  \
                  severity-roll-up   for every record, set `severity_rollup`. With --policies, \
                                     rule records take max(rule.severity, policy.severity).\n  \
                  repo-owner         hoist `repo.owner` to a top-level `_repo_owner` field. \
                                     Records without a repo pass through.\n\n\
                  Auxiliary records come from --policies <FILE> (JSONL of policy records). \
                  Streaming auxiliary fetch via the API will land in a later slice.\n\n\
                  Examples:\n  \
                  cat rules.jsonl | sidestep enrich --with policy-context --policies policies.jsonl\n  \
                  sidestep list rules --owner arcaven | sidestep enrich --with severity-roll-up \\\n  \
                                                                          --policies policies.jsonl"
)]
struct EnrichArgs {
    /// Recipe name. One of: policy-context, severity-roll-up, repo-owner.
    #[arg(long = "with", value_name = "RECIPE")]
    recipe: String,

    /// Auxiliary stream of policy records as JSONL.
    /// Required by `policy-context`; optional but recommended for
    /// `severity-roll-up` (without it, rule records can't roll up to
    /// their parent policy's severity).
    #[arg(long, value_name = "FILE")]
    policies: Option<std::path::PathBuf>,
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
        Cmd::Get(args) => run_get(args),
        Cmd::Search(args) => run_search(args),
        Cmd::Emit(args) => run_emit(args),
        Cmd::Filter(args) => run_filter(args),
        Cmd::Enrich(args) => run_enrich(args),
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

    // Validate --since before any network call so format errors don't
    // burn an API request (or a YubiKey tap, for tokens routed through
    // hardware-backed keychains).
    let since_program = build_since_program(spec, args.since.as_deref())?;
    let params = build_params(
        &args.params,
        args.owner.as_deref(),
        args.repo.as_deref(),
        &[],
    )?;
    let response = call_op_blocking(op_id, params, args.no_audit)?;
    let items_owned: Vec<Value> = match kinds::extract_items(&response) {
        Some(items) => items.to_vec(),
        None => vec![response],
    };

    let now = chrono_now();

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut emitted = 0usize;
    for (idx, item) in items_owned.into_iter().enumerate() {
        let record = Record::wrap(spec.name, SourceRef::now(op_id, idx), item);
        if let Some(prog) = &since_program {
            if !cel::evaluate(prog, &record, now, "<--since predicate>")
                .map_err(|e| anyhow!("{e}"))?
            {
                continue;
            }
        }
        write_record(&mut out, &record).map_err(|e| anyhow!("{e}"))?;
        emitted += 1;
        if let Some(limit) = args.limit
            && emitted >= limit
        {
            break;
        }
    }
    Ok(())
}

fn run_get(args: GetArgs) -> anyhow::Result<()> {
    let spec = kind_spec(&args.kind).ok_or_else(|| {
        anyhow!(
            "unknown kind '{}' — run with --help to see the v0.1 set",
            args.kind
        )
    })?;
    let op_id = spec.get_operation_id.ok_or_else(|| {
        anyhow!(
            "kind '{}' has no get-by-id endpoint in v0.1 — try `sidestep list {} | sidestep filter --where 'id == \"<your-id>\"'`",
            spec.name,
            spec.name
        )
    })?;
    let id_param = spec.id_path_param.ok_or_else(|| {
        anyhow!(
            "kind '{}' has a get endpoint but no declared id path parameter — file a bug",
            spec.name
        )
    })?;

    let extra = vec![(id_param.to_string(), Value::String(args.id.clone()))];
    let params = build_params(
        &args.params,
        args.owner.as_deref(),
        args.repo.as_deref(),
        &extra,
    )?;

    let response = call_op_blocking(op_id, params, args.no_audit)?;
    let record = Record::wrap(spec.name, SourceRef::now(op_id, 0), response);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    write_record(&mut out, &record).map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

fn run_search(args: SearchArgs) -> anyhow::Result<()> {
    let spec = kind_spec(&args.kind).ok_or_else(|| {
        anyhow!(
            "unknown kind '{}' — run with --help to see the v0.1 set",
            args.kind
        )
    })?;
    let op_id = spec.list_operation_id.ok_or_else(|| {
        anyhow!(
            "kind '{}' has no list endpoint in v0.1 — search composes on top of list",
            spec.name
        )
    })?;
    let search_field = spec.search_field.ok_or_else(|| {
        anyhow!(
            "kind '{}' has no search field declared in v0.1 — operators compose `list | filter` instead",
            spec.name
        )
    })?;

    let params = build_params(
        &args.params,
        args.owner.as_deref(),
        args.repo.as_deref(),
        &[],
    )?;
    let response = call_op_blocking(op_id, params, args.no_audit)?;
    let items_owned: Vec<Value> = match kinds::extract_items(&response) {
        Some(items) => items.to_vec(),
        None => vec![response],
    };

    let needle = args.query.to_lowercase();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut emitted = 0usize;
    for (idx, item) in items_owned.into_iter().enumerate() {
        let record = Record::wrap(spec.name, SourceRef::now(op_id, idx), item);
        let Some(field_value) = record.get(search_field) else {
            continue;
        };
        let Some(haystack) = field_value.as_str() else {
            continue;
        };
        if !haystack.to_lowercase().contains(&needle) {
            continue;
        }
        write_record(&mut out, &record).map_err(|e| anyhow!("{e}"))?;
        emitted += 1;
        if let Some(limit) = args.limit
            && emitted >= limit
        {
            break;
        }
    }
    Ok(())
}

fn build_params(
    raw: &[String],
    owner: Option<&str>,
    repo: Option<&str>,
    extras: &[(String, Value)],
) -> anyhow::Result<Value> {
    let mut params = parse_params(raw)?;
    if let Some(o) = owner {
        params.insert("owner".to_string(), Value::String(o.to_string()));
    }
    if let Some(r) = repo {
        params.insert("repo".to_string(), Value::String(r.to_string()));
    }
    for (k, v) in extras {
        params.insert(k.clone(), v.clone());
    }
    Ok(Value::Object(params))
}

fn call_op_blocking(op_id: &str, params: Value, no_audit: bool) -> anyhow::Result<Value> {
    let client = Client::from_env().map_err(|e| anyhow!("{e}"))?;
    let opts = CallOptions {
        no_audit,
        ..Default::default()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime
        .block_on(client.call_op(op_id, &params, opts))
        .map_err(|e| anyhow!("{e}"))
}

/// Build a CEL post-filter program for `--since <duration>`. Returns
/// `None` when `--since` was not supplied. Errors when the kind has no
/// primary timestamp field — `--since` has no field to compare against.
///
/// The compiled predicate is `<primary_ts_field> > now - duration("<dur>")`,
/// reusing the cel adapter so timestamp promotion + `now` binding apply
/// consistently. CEL's `duration()` accepts Go-style durations
/// (`24h`, `30m`, `1h30m`). cel-rust 0.10 accepts malformed inputs at
/// compile time and only fails at runtime, so we pre-validate here to
/// fail before any network call.
fn build_since_program(
    spec: &sidestep_sdk::KindSpec,
    since: Option<&str>,
) -> anyhow::Result<Option<cel_interpreter::Program>> {
    let Some(dur) = since else {
        return Ok(None);
    };
    let ts_field = spec.primary_timestamp_field.ok_or_else(|| {
        anyhow!(
            "kind '{}' has no primary timestamp field — `--since` is not applicable",
            spec.name
        )
    })?;
    if dur.contains('"') {
        return Err(anyhow!("--since must not contain quotes: {dur:?}"));
    }
    if !is_valid_go_duration(dur) {
        return Err(anyhow!(
            "--since: invalid duration {dur:?} — expected Go-style (e.g. 24h, 30m, 1h30m). \
             Valid units: ns, us, µs, ms, s, m, h."
        ));
    }
    let predicate = format!(r#"{ts_field} > now - duration("{dur}")"#);
    let program = cel::compile(&predicate).map_err(|e| anyhow!("--since: {e}"))?;
    Ok(Some(program))
}

/// Lightweight Go-duration validator. Accepts a non-empty sequence of
/// `<number><unit>` pairs where units are one of `ns`, `us`, `µs`, `ms`,
/// `s`, `m`, `h`. Numbers may carry a single decimal point. Empty input
/// or missing/unknown units fail.
fn is_valid_go_duration(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars().peekable();
    let mut had_pair = false;
    while chars.peek().is_some() {
        let mut saw_digit = false;
        let mut saw_dot = false;
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                saw_digit = true;
                chars.next();
            } else if c == '.' && !saw_dot {
                saw_dot = true;
                chars.next();
            } else {
                break;
            }
        }
        if !saw_digit {
            return false;
        }
        let mut unit = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphabetic() || c == 'µ' {
                unit.push(c);
                chars.next();
            } else {
                break;
            }
        }
        match unit.as_str() {
            "ns" | "us" | "µs" | "ms" | "s" | "m" | "h" => had_pair = true,
            _ => return false,
        }
    }
    had_pair
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

fn run_enrich(args: EnrichArgs) -> anyhow::Result<()> {
    let recipe = enrich::Recipe::parse(&args.recipe).ok_or_else(|| {
        anyhow!(
            "unknown recipe '{}'. v0.1 recipes: policy-context, severity-roll-up, repo-owner",
            args.recipe
        )
    })?;

    let ctx = build_enrichment_context(args.policies.as_deref())?;
    ctx.validate_for(recipe).map_err(|e| anyhow!("{e}"))?;

    let stdin = std::io::stdin();
    let stdin = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for record in read_stream(stdin) {
        let record = record.map_err(|e| anyhow!("{e}"))?;
        let enriched = enrich::apply(recipe, record, &ctx);
        write_record(&mut out, &enriched).map_err(|e| anyhow!("{e}"))?;
    }
    Ok(())
}

fn build_enrichment_context(
    policies_path: Option<&std::path::Path>,
) -> anyhow::Result<enrich::EnrichmentContext> {
    let Some(path) = policies_path else {
        return Ok(enrich::EnrichmentContext::default());
    };
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let policies: Vec<Record> = read_stream(reader)
        .collect::<sidestep_sdk::Result<Vec<_>>>()
        .map_err(|e| anyhow!("read --policies {}: {e}", path.display()))?;
    if policies.iter().any(|p| p.kind != "policy") {
        return Err(anyhow!(
            "--policies {} contains records of kinds other than `policy`",
            path.display()
        ));
    }
    Ok(enrich::EnrichmentContext::with_policies(policies))
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

#[cfg(test)]
mod since_tests {
    use super::is_valid_go_duration;

    #[test]
    fn accepts_simple_units() {
        assert!(is_valid_go_duration("24h"));
        assert!(is_valid_go_duration("30m"));
        assert!(is_valid_go_duration("60s"));
        assert!(is_valid_go_duration("500ms"));
        assert!(is_valid_go_duration("100ns"));
        assert!(is_valid_go_duration("100us"));
        assert!(is_valid_go_duration("100µs"));
    }

    #[test]
    fn accepts_compound_durations() {
        assert!(is_valid_go_duration("1h30m"));
        assert!(is_valid_go_duration("2h45m30s"));
    }

    #[test]
    fn accepts_decimal() {
        assert!(is_valid_go_duration("1.5h"));
        assert!(is_valid_go_duration("0.25s"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_valid_go_duration(""));
    }

    #[test]
    fn rejects_unknown_unit() {
        assert!(!is_valid_go_duration("7d"));
        assert!(!is_valid_go_duration("1w"));
    }

    #[test]
    fn rejects_no_unit() {
        assert!(!is_valid_go_duration("24"));
    }

    #[test]
    fn rejects_no_number() {
        assert!(!is_valid_go_duration("h"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(!is_valid_go_duration("not-a-real-duration"));
        assert!(!is_valid_go_duration("24h-extra"));
    }
}
