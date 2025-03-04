# CLAUDE.md for pfp.blue

## Build/Lint/Test Commands

- Build: `cargo build`
- Run: `cargo run`
- Check: `cargo check`
- Lint: `cargo clippy`
- Format: `cargo fmt`
- Test: `cargo test`
- Test single: `cargo test <test_name>`
- Run database migrations: `sqlx migrate run`

## Code Style Guidelines

- Error handling: Use `cja::Result`, propagate with `?` operator
- Naming: snake_case for variables/functions, CamelCase for types, UPPERCASE for constants
- Imports: Group by crate, organize logically, prefer explicit imports
- Async: Use async/await throughout with Tokio runtime
- State: Pass AppState as context throughout application
- Modules: Organize by functionality (routes, jobs, etc.)
- Documentation: Document public interfaces
- Error messages: Be descriptive and actionable
- Error propagation: Use `?` operator, avoid unwrap/expect in production code
- Tracing: Use tracing macros for observability (info, debug, etc.)
