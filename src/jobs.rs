use cja::jobs::Job;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

cja::impl_job_registry!(AppState, NoopJob);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NoopJob;

#[async_trait::async_trait]
impl Job<AppState> for NoopJob {
    const NAME: &'static str = "NoopJob";

    async fn run(&self, _app_state: AppState) -> cja::Result<()> {
        Ok(())
    }
}
