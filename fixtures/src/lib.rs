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

    /// Force allow running without required environment variables (for development)
    #[arg(long)]
    pub force: bool,
}

/// Helper to get a required environment variable or return an error
pub fn require_env_var(name: &str, force: bool) -> anyhow::Result<String> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(_) => {
            if force {
                error!("WARNING: Required environment variable {} not set. Using placeholder value because --force was specified.", name);
                Ok("http://localhost:3000".to_string())
            } else {
                anyhow::bail!(
                    "Required environment variable {} not set. Use --force to bypass this check.",
                    name
                )
            }
        }
    }
}

/// Common function to run a fixture server
pub async fn run_server(args: FixtureArgs, app: Router) -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let addr = format!("{}:{}", args.host, args.port)
        .parse::<SocketAddr>()
        .unwrap();

    let app = app.layer(TraceLayer::new_for_http());

    info!("Fixture server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
