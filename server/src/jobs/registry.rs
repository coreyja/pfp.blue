use cja::jobs::Job;
use color_eyre::eyre::Context as _;
use std::collections::HashMap;
use std::str::FromStr;

use crate::jobs::job_types::{NoopJob, UpdateProfileInfoJob, UpdateProfilePictureProgressJob};
use crate::state::AppState;

/// Helper function to get a list of all available job types
pub fn get_available_jobs() -> Vec<&'static str> {
    vec![
        NoopJob::NAME,
        UpdateProfileInfoJob::NAME,
        UpdateProfilePictureProgressJob::NAME,
    ]
}

// Define a JobType enum to represent our different job types
#[derive(Debug, Clone)]
pub enum JobType {
    Noop(NoopJob),
    UpdateProfileInfo(UpdateProfileInfoJob),
    UpdateProfilePicture(UpdateProfilePictureProgressJob),
}

impl JobType {
    pub async fn run(&self, app_state: AppState) -> cja::Result<()> {
        match self {
            JobType::Noop(job) => job.run(app_state).await,
            JobType::UpdateProfileInfo(job) => job.run(app_state).await,
            JobType::UpdateProfilePicture(job) => job.run(app_state).await,
        }
    }

    pub async fn enqueue(&self, app_state: AppState) -> cja::Result<()> {
        // Create a context string for the job enqueue
        let context = format!("admin_panel_enqueue_{}", self.name());

        // Match on the job type and enqueue the job with the context
        let result = match self {
            JobType::Noop(job) => {
                let job_clone = job.clone();
                job_clone.enqueue(app_state, context).await
            }
            JobType::UpdateProfileInfo(job) => {
                let job_clone = job.clone();
                job_clone.enqueue(app_state, context).await
            }
            JobType::UpdateProfilePicture(job) => {
                let job_clone = job.clone();
                job_clone.enqueue(app_state, context).await
            }
        };

        // Convert the EnqueueError to cja::Result
        result.wrap_err("Failed to enqueue job")
    }

    pub fn name(&self) -> &'static str {
        match self {
            JobType::Noop(_) => NoopJob::NAME,
            JobType::UpdateProfileInfo(_) => UpdateProfileInfoJob::NAME,
            JobType::UpdateProfilePicture(_) => UpdateProfilePictureProgressJob::NAME,
        }
    }
}

/// Helper function to create a job from its name and args
pub fn create_job_from_name_and_args(
    job_name: &str,
    args: HashMap<String, String>,
) -> Result<JobType, String> {
    match job_name {
        NoopJob::NAME => Ok(JobType::Noop(NoopJob)),

        UpdateProfileInfoJob::NAME => {
            let did = args.get("did").ok_or("Missing required arg: did")?;
            Ok(JobType::UpdateProfileInfo(UpdateProfileInfoJob {
                did: did.clone(),
            }))
        }

        UpdateProfilePictureProgressJob::NAME => {
            let token_id_str = args
                .get("token_id")
                .ok_or("Missing required arg: token_id")?;
            let token_id = uuid::Uuid::from_str(token_id_str)
                .map_err(|e| format!("Invalid UUID for token_id: {}", e))?;
            Ok(JobType::UpdateProfilePicture(
                UpdateProfilePictureProgressJob { token_id },
            ))
        }

        _ => Err(format!("Unknown job type: {}", job_name)),
    }
}

/// Get parameter descriptions for a job
pub fn get_job_params(job_name: &str) -> Vec<(String, String, bool)> {
    match job_name {
        NoopJob::NAME => Vec::new(),

        UpdateProfileInfoJob::NAME => vec![(
            "did".to_string(),
            "DID string (e.g., did:plc:abcdef...)".to_string(),
            true,
        )],

        UpdateProfilePictureProgressJob::NAME => vec![(
            "token_id".to_string(),
            "UUID of the OAuth token".to_string(),
            true,
        )],

        _ => Vec::new(),
    }
}

// This implements the Jobs struct required by the cja job worker
cja::impl_job_registry!(
    AppState,
    NoopJob,
    UpdateProfileInfoJob,
    UpdateProfilePictureProgressJob
);
