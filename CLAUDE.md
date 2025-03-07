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
