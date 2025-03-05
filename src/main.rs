use cja::{
    app_state::AppState as _,
    server::run_server,
    setup::{setup_sentry, setup_tracing},
};
use tracing::info;

mod cron;
mod did;
mod jobs;
mod oauth;
mod routes;
mod state;

use state::AppState;

fn main() -> color_eyre::Result<()> {
    let _sentry_guard = setup_sentry();

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(async { _main().await })
}

async fn _main() -> cja::Result<()> {
    setup_tracing("domains")?;

    println!("\n========== 🔑 PFP.BLUE STARTING ==========");
    println!("Verifying OAuth keys...");

    let app_state = match AppState::from_env().await {
        Ok(state) => {
            println!("✅ OAuth keys verified successfully!\n");
            state
        }
        Err(e) => {
            eprintln!("\n❌ ERROR: Failed to initialize app state: {}", e);
            eprintln!("Please check your OAuth key configuration. Keys should be in PEM format with proper newlines.");
            eprintln!("You can run the setup_keys.sh script to generate new keys.\n");
            return Err(e);
        }
    };

    cja::sqlx::migrate!().run(app_state.db()).await?;

    info!("Spawning Tasks");
    let mut futures = vec![tokio::spawn(run_server(routes::routes(app_state.clone())))];
    if std::env::var("JOBS_DISABLED").unwrap_or_else(|_| "false".to_string()) != "true" {
        info!("Jobs Enabled");
        futures.push(tokio::spawn(cja::jobs::worker::job_worker(
            app_state.clone(),
            jobs::Jobs,
        )));
    }
    if std::env::var("CRON_DISABLED").unwrap_or_else(|_| "false".to_string()) != "true" {
        info!("Cron Enabled");
        futures.push(tokio::spawn(cron::run_cron(app_state.clone())));
    }
    info!("Tasks Spawned");

    futures::future::try_join_all(futures).await?;

    Ok(())
}
