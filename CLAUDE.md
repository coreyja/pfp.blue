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

3. Implement an enqueue method for the job:
```rust
impl MyJob {
    /// Queue this job to run asynchronously
    pub async fn enqueue(self, app_state: &AppState) -> cja::Result<()> {
        // Jobs are enqueued into the database
        let pool = &app_state.db;
        
        let job_data = serde_json::to_value(&self)?;
            
        sqlx::query(
            r#"
            INSERT INTO jobs (job_type, retries_remaining, data) 
            VALUES ($1, $2, $3)
            "#
        )
        .bind(Self::NAME)
        .bind(3) // Allow up to 3 retries
        .bind(job_data)
        .execute(pool)
        .await?;
        
        Ok(())
    }
}
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
