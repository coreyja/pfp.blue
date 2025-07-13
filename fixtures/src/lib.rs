use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use clap::Parser;
use std::env;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

/// Common CLI arguments for all fixture servers
#[derive(Parser, Debug, Clone)]
pub struct FixtureArgs {
    /// The port to listen on
    #[arg(short, long, default_value = "0")]
    pub port: u16,

    /// The host to bind to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,
}

/// Helper to get a required environment variable or return an error
pub fn require_env_var(name: &str) -> anyhow::Result<String> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(_) => {
            anyhow::bail!("Required environment variable {} not set", name)
        }
    }
}

/// Logging middleware for requests and responses
pub async fn logging_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Log the request
    info!("==== INCOMING REQUEST ====");
    info!("{} {}", method, uri);
    info!("Headers: {:#?}", headers);

    // Extract and log the body if it's not too large
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            error!("Failed to read request body");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    if !bytes.is_empty() {
        match std::str::from_utf8(&bytes) {
            Ok(body_str) => {
                info!("Body: {}", body_str);
            }
            Err(_) => {
                info!("Body: <binary data, {} bytes>", bytes.len());
            }
        }
    }

    // Reconstruct the request
    let req = Request::from_parts(parts, Body::from(bytes));

    // Call the next handler
    let response = next.run(req).await;

    // Log the response
    let (parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            error!("Failed to read response body");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    info!("==== OUTGOING RESPONSE ====");
    info!("Status: {}", parts.status);
    info!("Headers: {:#?}", parts.headers);

    if !bytes.is_empty() {
        match std::str::from_utf8(&bytes) {
            Ok(body_str) => {
                info!("Body: {}", body_str);
            }
            Err(_) => {
                info!("Body: <binary data, {} bytes>", bytes.len());
            }
        }
    }
    info!("============================\n");

    // Reconstruct the response
    Ok(Response::from_parts(parts, Body::from(bytes)))
}

/// Common function to run a fixture server
pub async fn run_server(args: FixtureArgs, app: Router) -> anyhow::Result<()> {
    // Initialize tracing - check for FIXTURE_LOG_FILE environment variable
    if let Ok(log_file_path) = env::var("FIXTURE_LOG_FILE") {
        // Set up file logging without ANSI colors
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)?;

        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false) // Disable ANSI colors for file output
            .with_target(true) // Optional: disable target info for cleaner logs
            .with_writer(std::sync::Arc::new(file));

        tracing_subscriber::registry()
            .with(file_layer)
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .init();

        info!("Logging to file: {}", log_file_path);
    } else {
        // Default console logging with colors
        tracing_subscriber::fmt::init();
    }

    let addr = format!("{}:{}", args.host, args.port)
        .parse::<SocketAddr>()
        .unwrap();

    let app = app
        .layer(middleware::from_fn(logging_middleware))
        .layer(TraceLayer::new_for_http());

    info!("Fixture server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Database module for fixture servers
pub mod db {
    use sqlx::{Pool, Sqlite, SqlitePool};
    use tracing::info;

    /// Initialize an in-memory SQLite database
    pub async fn init_database() -> anyhow::Result<Pool<Sqlite>> {
        info!("Initializing in-memory SQLite database");

        // Create an in-memory SQLite database
        let pool = SqlitePool::connect("sqlite::memory:").await?;

        // Create the schema for PAR requests
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS par_requests (
                request_uri TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                state TEXT,
                code_challenge TEXT,
                code_challenge_method TEXT,
                scope TEXT,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&pool)
        .await?;

        // Create the schema for authorization codes
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth_codes (
                code TEXT PRIMARY KEY,
                request_uri TEXT,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                user_did TEXT NOT NULL,
                user_handle TEXT NOT NULL,
                scope TEXT,
                code_challenge TEXT,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )
            "#,
        )
        .execute(&pool)
        .await?;

        info!("Database schema created successfully");
        Ok(pool)
    }
}
