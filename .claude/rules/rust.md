# Rust Coding Rules

## Safety

```rust
// Every binary and library crate
#![forbid(unsafe_code)]
```

- No `unwrap()` in production code — use `?` or `expect()` with actionable message
- `unwrap()` is acceptable in tests

## Type Design

- **Newtypes for IDs:** prevents mixing ID types
- **Validated constructors at trust boundaries:** `new()` validates (CLI input, file parsing, API responses)
- **`#[non_exhaustive]` on enums that will grow** — forces callers to handle future variants
- **Private fields with getters** on types where invariants must hold

## Error Handling

```rust
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SidestepError {
    // Semantic variants per domain
}

pub type Result<T> = std::result::Result<T, SidestepError>;
```

- Use `thiserror` for error enums — structured variants, not string bags
- Define `pub type Result<T>` per crate for ergonomics
- `Display` impl is for user-facing output in a CLI — be clear and actionable

## Generated code

`crates/sidestep-api/` is regenerated from `spec/stepsecurity-v1.yaml` via
`cargo xtask regen`. Do not hand-edit generated source files; change the
spec or the generator config and regenerate.

## Async Conventions

- Use `tokio` runtime; single runtime per binary
- Prefer `tokio::task::spawn_blocking` for CPU-bound work
- `tracing` for structured async logging; `tracing-subscriber` in binaries only
- Don't hold locks across `.await` points

## Testing

- Unit: `#[cfg(test)] mod tests {}` in same file
- Integration: `tests/` directory per crate
- Test names as documentation: `audit_redacts_authorization_header()`, not `test_1()`
- `wiremock` for HTTP mocking; `insta` for response snapshots
- Mark independent tests with `#[tokio::test]` or `t.parallel()` where safe

## Common AI mistakes to avoid

1. Don't add unused trait parameters "for future use" — YAGNI
2. Don't panic in library code — return `Result`
3. Don't use `unwrap()` outside tests
4. Don't expose `String` when a newtype clarifies intent
5. Don't block the async runtime — use `spawn_blocking` for CPU work
6. Don't ignore `cargo clippy` warnings — they catch real bugs
7. Don't comment out generated code; regenerate from spec instead
