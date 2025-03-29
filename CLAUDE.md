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
- Create migration: `sqlx migrate add --source migrations <migration_name>`
- Recreate DB from scratch: `cargo sqlx db drop -y && cargo sqlx db create && cargo sqlx migrate run`
- Run all CI checks locally: `./scripts/local-ci.sh` (run this before committing/pushing)

## Background Jobs

For background work, don't use `tokio::spawn`. Instead, use the cja job system:

1. Create a new job struct that implements the `Job` trait (must also implement Default):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MyJob {
    // Store MINIMAL data needed to identify work - prefer database IDs
    // Don't store data that can be looked up from the database
    pub entity_id: i32, // Example: just store the ID of what to process
}

#[async_trait::async_trait]
impl Job<AppState> for MyJob {
    const NAME: &'static str = "MyJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        // Look up latest data from the database
        let entity = get_entity_by_id(&app_state.db, self.entity_id).await?;

        // Process using the latest data from the database
        Ok(())
    }
}
```

2. Add the job to the job registry in `src/jobs.rs`:

```rust
// Add to the macro call
cja::impl_job_registry!(AppState, NoopJob, UpdateProfileHandleJob, MyJob);
```

4. To enqueue a job for background processing:

```rust
MyJob { some_field: "value".to_string() }
    .enqueue(&app_state)
    .await?;
```

Jobs are processed in the background and will retry on failure.

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

## Error Handling Guidelines

We use `color-eyre` for error handling throughout the codebase. Follow these best practices:

1. Always prefer using the `?` operator with `wrap_err` or `wrap_err_with` instead of match statements for error handling:

```rust
// GOOD
let data = some_function().wrap_err("Failed to get data")?;

// AVOID when only adding context
let data = match some_function() {
    Ok(d) => d,
    Err(e) => return Err(eyre!("Failed to get data: {}", e)),
};
```

2. Use `wrap_err` for static error messages:

```rust
// GOOD
.wrap_err("Failed to decode file")?;

// AVOID for static strings 
.wrap_err_with(|| "Failed to decode file")?;
```

3. Use `wrap_err_with` only when you need to generate dynamic error messages:

```rust
// GOOD - Dynamic content in error message
.wrap_err_with(|| format!("Failed to process file: {}", file_path))?;

// GOOD - Expensive computation only done if there's an error
.wrap_err_with(|| {
    let details = compute_error_details();
    format!("Failed with details: {}", details)
})?;
```

4. Always ensure the `WrapErr` trait is imported:

```rust
use color_eyre::eyre::{eyre, WrapErr};
```

5. For web handlers, use the `ServerResult` type alias to handle errors consistently:

```rust
// Handler function signature pattern
async fn my_handler(
    State(state): State<AppState>,
    // ... other parameters
) -> ServerResult<impl IntoResponse, StatusCode> {
    // Function logic
    let result = some_operation().await
        .wrap_err("Failed to perform operation")?;
    
    Ok(result.into_response())
}
```

For handlers that need to return redirects on error:

```rust
async fn profile_handler(
    // ... parameters
) -> ServerResult<impl IntoResponse, Redirect> {
    let user_data = get_user_data().await
        .wrap_err("Failed to get user data")
        .with_redirect(Redirect::to("/login"))?;
    
    Ok(render_profile(user_data).into_response())
}
```

6. Use the following traits for converting errors to appropriate responses:

```rust
// For StatusCode responses
.with_status(StatusCode::BAD_REQUEST)?

// For Redirect responses
.with_redirect(Redirect::to("/error-page"))?
```

Important: Always import the necessary types and traits:

```rust
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use crate::errors::{ServerResult, ServerError, WithStatus, WithRedirect};
use color_eyre::eyre::{eyre, WrapErr};
```

The `ServerResult` type alias is defined as:

```rust
// Type alias for server handler results
pub type ServerResult<S, F> = Result<S, ServerError<F>>;

// ServerError wraps an eyre::Report with a response type
pub struct ServerError<R: IntoResponse>(pub(crate) cja::color_eyre::Report, pub(crate) R);
```

This pattern allows us to:
1. Include detailed error information (via Report)
2. Specify exactly what kind of response should be returned on error
3. Maintain type safety throughout our error handling

Remember the difference between `wrap_err` and `with_status`/`with_redirect`:
- `wrap_err` adds context to the error for debugging and logging
- `with_status`/`with_redirect` converts the error into an appropriate HTTP response
- Typically use them together: `operation().wrap_err("context").with_status(StatusCode::BAD_REQUEST)?`

7. Database queries: **Always** use the `sqlx::query!` and `sqlx::query_as!` macros instead of the non-macro versions. These macros provide compile-time SQL validation and type-checking, preventing runtime SQL errors.

## Database Schema

Key tables and their primary key columns:

- `users`: `id` (UUID)
- `sessions`: `id` (UUID)
- `oauth_tokens`: `id` (UUID) and `uuid_id` (UUID) - the latter is used for foreign keys
- `oauth_sessions`: `id` (UUID)
- `jobs`: `job_id` (UUID)
- `crons`: `cron_id` (UUID)
- `profile_picture_progress`: `id` (UUID)

All UUID columns have the default value set to `gen_random_uuid()`.

Important relationships:

- `oauth_tokens.user_id` references `users.id`
- `sessions.user_id` references `users.id`
- `sessions.primary_token_id` references `oauth_tokens.uuid_id`
- `profile_picture_progress.token_id` references `oauth_tokens.id`

When adding new tables, ensure:

1. UUID primary keys use `gen_random_uuid()` as default
2. Foreign keys reference the correct column (check if it's `id` or a different name)
3. Include the proper timestamps (`created_at_utc` and `updated_at_utc`)

## Authentication System

The project uses a multi-layered authentication system:

1. OAuth integration with Bluesky for authentication
2. Session system for maintaining user state
3. Linked accounts system where multiple Bluesky accounts can be linked to one user

Key components:

- `OAuthSession` - Temporary session for OAuth flow
- `OAuthTokenSet` - Stores access tokens, refresh tokens, etc.
- `Session` - User session after authentication
- `User` - Represents a user in the system

OAuth flow creates `OAuthSession`, which leads to `OAuthTokenSet`, which can be associated with `User`. A `Session` is created for the user when they authenticate.

## CI/CD and Quality Checks

Before committing or pushing code, run the local CI checks to ensure your changes will pass in the GitHub Actions workflow:

```
./scripts/local-ci.sh
```

This script runs the following checks:

1. Verifies PostgreSQL is running
2. Prepares the test database with migrations
3. Verifies SQLx prepared queries are up-to-date (`cargo sqlx prepare --workspace --check`)
4. Checks code formatting (`cargo fmt --all --check`)
5. Runs clippy lints (`cargo clippy --all-targets --workspace`)
6. Runs all tests (`cargo test --all-targets`)
7. If installed, runs cargo-deny to check for prohibited dependencies (`cargo-deny check bans`)

If any of these checks fail, the script will stop and show the error. Fix the issues before committing your changes.

### Important Pre-Commit Steps

Always run these commands before committing:

1. **After changing any SQL queries**: Run `cargo sqlx prepare --workspace` to update the prepared queries
2. **Before each commit**: Run `cargo fmt` to format all code consistently

These steps ensure CI will pass and maintain consistent code style throughout the project.

## End-to-End Testing

**ALL user-facing features must have end-to-end test coverage.** We use Playwright for our end-to-end tests.

To run the end-to-end tests:

```bash
# Install dependencies
pnpm install

# Recommended way: use the test script (supports fixtures)
pnpm e2e

# Run with specific options
./scripts/run-e2e-tests.sh --browser firefox --test auth
./scripts/run-e2e-tests.sh --debug --test "profile picture"

# Traditional commands
pnpm test              # Run all tests
pnpm test:ui           # Run tests with UI mode (useful for debugging)
pnpm test:headed       # Run tests in headed mode (shows browser)

# Run against fixtures (mock services)
pnpm test:fixtures          # Run all tests with fixtures
pnpm test:fixtures:ui       # Run tests with UI mode using fixtures
pnpm test:fixtures:headed   # Run tests in headed mode using fixtures

# Run tests in a specific browser
pnpm test:chrome
pnpm test:firefox
pnpm test:safari

# Show the last test report
pnpm report        # View report in terminal
pnpm report:open   # Open report in browser with screenshots
```

### Test Script Options

The `run-e2e-tests.sh` script provides a convenient way to run tests:

```
Usage: ./scripts/run-e2e-tests.sh [options]

Options:
  --browser, -b <browser>   Specify browser (chromium, firefox, webkit)
  --headless                Run in headless mode
  --no-fixtures             Don't use fixture servers (uses real services)
  --real-services           Same as --no-fixtures
  --test, -t <pattern>      Run tests matching pattern
  --debug, -d               Run tests in debug mode
  --help, -h                Show this help message
```

### Adding New Tests

When adding a new user-facing feature:

1. Create corresponding end-to-end tests in the `end2end/` directory
2. Test both happy paths and error cases
3. For features requiring authentication, use the authentication fixtures
4. Make tests work with both real services and fixtures where possible

The fixtures provide a test user with:

- Handle: `fixture-user.test`
- DID: `did:plc:abcdefg`

### Test Structure

Current test structure:

- `end2end/homepage.spec.ts` - Tests for homepage and navigation
- `end2end/auth.spec.ts` - Tests for authentication flows
- `end2end/profile.spec.ts` - Tests for profile management features
- `end2end/fixtures.ts` - Shared test fixtures and utilities
