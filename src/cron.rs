use cja::cron::{CronRegistry, Worker};
use tracing::{error, info};

use crate::{oauth, state::AppState};

fn cron_registry() -> CronRegistry<AppState> {
    let mut registry = CronRegistry::new();

    // Add a job to clean up expired OAuth sessions every hour
    registry.register(
        "cleanup_expired_oauth_sessions",
        std::time::Duration::from_secs(60 * 60), // Run every hour
        |state: AppState, _job_name: String| {
            Box::pin(async move {
                if let Err(err) = cleanup_expired_sessions(state).await {
                    tracing::error!("Failed to run cleanup_expired_sessions: {:?}", err);
                }
                Ok::<_, std::convert::Infallible>(())
            })
        },
    );

    registry
}

pub(crate) async fn run_cron(app_state: AppState) -> cja::Result<()> {
    Ok(Worker::new(app_state, cron_registry()).run().await?)
}

/// Clean up expired OAuth sessions
async fn cleanup_expired_sessions(state: AppState) -> cja::Result<()> {
    info!("Cleaning up expired OAuth sessions");

    match oauth::db::cleanup_expired_sessions(&state.db).await {
        Ok(count) => {
            info!("Removed {} expired OAuth sessions", count);
            Ok(())
        }
        Err(err) => {
            error!("Failed to clean up expired OAuth sessions: {:?}", err);
            Err(err)
        }
    }
}
