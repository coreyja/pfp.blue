use cja::{
    app_state::AppState as _,
    server::run_server,
    setup::{setup_sentry, setup_tracing},
};
use tracing::info;

mod cron;
mod jobs;
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

    let app_state = AppState::from_env().await?;

    cja::sqlx::migrate!().run(app_state.db()).await?;

    info!("Spawning Tasks");
    let mut futures = vec![
        tokio::spawn(run_server(routes::routes(app_state.clone()))),
        tokio::spawn(cja::jobs::worker::job_worker(app_state.clone(), jobs::Jobs)),
    ];
    if std::env::var("CRON_DISABLED").unwrap_or_else(|_| "false".to_string()) != "true" {
        info!("Cron Enabled");
        futures.push(tokio::spawn(cron::run_cron(app_state.clone())));
    }
    info!("Tasks Spawned");

    futures::future::try_join_all(futures).await?;

    Ok(())
}
