use cja::{
    server::run_server,
    setup::{setup_sentry, setup_tracing},
};
use color_eyre::eyre::eyre;
use tracing::{error, info};

mod api;
mod auth;
mod cron;
mod did;
mod jobs;
mod oauth;
mod profile_progress;
mod routes;
mod state;
mod user;

use state::AppState;

/// Application entry point
fn main() -> color_eyre::Result<()> {
    // Initialize Sentry for error tracking
    let _sentry_guard = setup_sentry();

    // Create and run the tokio runtime
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(async { run_application().await })
}

/// Main application logic
async fn run_application() -> cja::Result<()> {
    // Initialize tracing
    setup_tracing("domains")?;

    // Initialize application state
    println!("\n========== 🔑 PFP.BLUE STARTING ==========");
    println!("Verifying OAuth keys...");

    let app_state = initialize_app_state().await?;

    // Set up application router
    let _app_router = routes::routes(app_state.clone());

    // Spawn application tasks
    info!("Spawning application tasks");
    let futures = spawn_application_tasks(app_state).await?;

    // Wait for all tasks to complete
    match futures::future::try_join_all(futures).await {
        Ok(_) => {
            info!("All application tasks completed normally");
            Ok(())
        }
        Err(e) => {
            error!("Error in application tasks: {:?}", e);
            Err(eyre!("Application tasks failed: {}", e))
        }
    }
}

/// Initialize application state
async fn initialize_app_state() -> cja::Result<AppState> {
    match AppState::from_env().await {
        Ok(state) => {
            println!("✅ OAuth keys verified successfully!\n");
            Ok(state)
        }
        Err(e) => {
            eprintln!("\n❌ ERROR: Failed to initialize app state: {}", e);
            eprintln!("Please check your OAuth key configuration. Keys should be in PEM format with proper newlines.");
            eprintln!("You can run the setup_keys.sh script to generate new keys.\n");
            Err(e)
        }
    }
}

/// Spawn all application background tasks
async fn spawn_application_tasks(
    app_state: AppState,
) -> cja::Result<Vec<tokio::task::JoinHandle<cja::Result<()>>>> {
    let mut futures = vec![tokio::spawn(run_server(routes::routes(app_state.clone())))];

    // Initialize job worker if enabled
    if is_feature_enabled("JOBS_DISABLED") {
        info!("Jobs Enabled");
        futures.push(tokio::spawn(cja::jobs::worker::job_worker(
            app_state.clone(),
            jobs::Jobs,
        )));
    } else {
        info!("Jobs Disabled");
    }

    // Initialize cron worker if enabled
    if is_feature_enabled("CRON_DISABLED") {
        info!("Cron Enabled");
        futures.push(tokio::spawn(cron::run_cron(app_state.clone())));
    } else {
        info!("Cron Disabled");
    }

    info!("All application tasks spawned successfully");
    Ok(futures)
}

/// Check if a feature is enabled based on environment variables
fn is_feature_enabled(env_var_name: &str) -> bool {
    std::env::var(env_var_name).unwrap_or_else(|_| "false".to_string()) != "true"
}
