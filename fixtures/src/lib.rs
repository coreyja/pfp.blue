use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::trace::TraceLayer;
use tracing::info;

/// Common CLI arguments for all fixture servers
#[derive(Parser, Debug, Clone)]
pub struct FixtureArgs {
    /// The port to listen on
    #[arg(short, long, default_value = "0")]
    pub port: u16,

    /// The host to bind to
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Path to JSON file with fixture data
    #[arg(short, long)]
    pub data: Option<PathBuf>,
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