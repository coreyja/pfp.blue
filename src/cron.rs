use cja::cron::{CronRegistry, Worker};
use tracing::{error, info};
use sqlx::Row;

use crate::{
    jobs::UpdateProfilePictureProgressJob, oauth, profile_progress::ProfilePictureProgress,
    state::AppState,
};

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

    // Add a job to update profile pictures with progress every hour
    registry.register(
        "update_profile_picture_progress",
        std::time::Duration::from_secs(60 * 60), // Run every hour
        |state: AppState, _job_name: String| {
            Box::pin(async move {
                if let Err(err) = update_profile_pictures(state).await {
                    tracing::error!("Failed to run update_profile_pictures: {:?}", err);
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

/// Update profile pictures for all enabled accounts
/// This function is called by the cron job every hour
async fn update_profile_pictures(state: AppState) -> cja::Result<()> {
    info!("Starting profile picture progress updates");

    // Find all tokens with enabled profile picture progress
    let rows = sqlx::query(
        r#"
        SELECT p.token_id 
        FROM profile_picture_progress p
        WHERE p.enabled = TRUE
        "#,
    )
    .fetch_all(&state.db)
    .await?;

    let count = rows.len();
    info!("Found {} enabled profile picture progress settings", count);

    // Enqueue a job for each enabled token
    for row in rows {
        let token_id: uuid::Uuid = row.get("token_id");

        // Create and enqueue the job
        let job = UpdateProfilePictureProgressJob::new(token_id);
        if let Err(err) = job.enqueue(&state).await {
            error!(
                "Failed to enqueue profile picture update job for token {}: {:?}",
                token_id, err
            );
        }
    }

    info!("Enqueued {} profile picture update jobs", count);
    Ok(())
}
