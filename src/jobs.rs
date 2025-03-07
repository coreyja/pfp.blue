use cja::jobs::Job;
use serde::{Deserialize, Serialize};

use crate::{oauth::OAuthTokenSet, state::AppState};

// This implements the Jobs struct required by the cja job worker
cja::impl_job_registry!(AppState, NoopJob, UpdateProfileHandleJob);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NoopJob;

#[async_trait::async_trait]
impl Job<AppState> for NoopJob {
    const NAME: &'static str = "NoopJob";

    async fn run(&self, _app_state: AppState) -> cja::Result<()> {
        Ok(())
    }
}

/// Job to update a user's profile handle in the database
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateProfileHandleJob {
    /// The DID of the user - only thing we need to look up the token in the DB
    pub did: String,
}

impl UpdateProfileHandleJob {
    /// Create a new job from an OAuthTokenSet
    pub fn from_token(token: &OAuthTokenSet) -> Self {
        Self {
            did: token.did.clone(),
        }
    }

    /// Queue this job to run asynchronously
    pub async fn enqueue(self, app_state: &AppState) -> cja::Result<()> {
        // Jobs are enqueued into the database
        let pool = &app_state.db;
        
        let job_data = serde_json::to_value(&self)
            .map_err(|e| color_eyre::eyre::eyre!("Failed to serialize job: {}", e))?;
            
        sqlx::query(
            r#"
            INSERT INTO jobs (job_type, retries_remaining, data) 
            VALUES ($1, $2, $3)
            "#
        )
        .bind(Self::NAME)
        .bind(3) // Allow up to 3 retries
        .bind(job_data)
        .execute(pool)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("Failed to enqueue job: {}", e))?;
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl Job<AppState> for UpdateProfileHandleJob {
    const NAME: &'static str = "UpdateProfileHandleJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        use color_eyre::eyre::eyre;
        use tracing::{debug, error, info};

        // First, get the current token from the database
        let token = match crate::oauth::db::get_token(&app_state.db, &self.did).await {
            Ok(Some(token)) => token,
            Ok(None) => {
                // No token found for this DID, can't proceed
                error!("No active token found for DID {} in job", self.did);
                return Err(eyre!("No active token found for DID"));
            }
            Err(err) => {
                error!("Error retrieving token for DID {}: {:?}", self.did, err);
                return Err(err);
            }
        };

        let client = reqwest::Client::new();

        // Create a DPoP proof for this API call
        let dpop_proof = match crate::oauth::create_dpop_proof(
            &app_state.bsky_oauth,
            "GET",
            "https://bsky.social/xrpc/com.atproto.repo.getRecord",
            None,
        ) {
            Ok(proof) => proof,
            Err(err) => {
                error!("Failed to create DPoP proof for profile job: {:?}", err);
                return Err(err);
            }
        };

        // Make the API request to get user profile
        let response = match client
            .get("https://bsky.social/xrpc/com.atproto.repo.getRecord")
            .query(&[
                ("repo", &self.did),
                ("collection", &String::from("app.bsky.actor.profile")),
                ("rkey", &String::from("self")),
            ])
            .header("Authorization", format!("DPoP {}", token.access_token))
            .header("DPoP", dpop_proof)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                error!("Failed to send profile request: {:?}", err);
                return Err(eyre!("Network error when fetching profile: {}", err));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            error!("Failed to fetch profile for {}: {} - {}", &self.did, status, error_text);
            return Err(eyre!(
                "Failed to fetch profile: {} - {}",
                status,
                error_text
            ));
        }

        // Parse the response JSON
        let profile_data = match response.json::<serde_json::Value>().await {
            Ok(data) => data,
            Err(err) => {
                error!("Failed to parse profile response: {:?}", err);
                return Err(eyre!("Failed to parse profile response: {}", err));
            }
        };

        // Extract the handle from the profile data
        let extracted_handle = if let Some(value) = profile_data.get("value") {
            if let Some(handle_val) = value.get("handle") {
                handle_val.as_str().map(|s| s.to_string())
            } else {
                None
            }
        } else {
            None
        };

        // If we found a handle in the profile, make sure it's updated in the database
        if let Some(handle_str) = extracted_handle {
            // Check if handle is different than what we have saved
            let should_update = match &token.handle {
                Some(current_handle) => current_handle != &handle_str,
                None => true, // No handle stored yet, need to update
            };

            if should_update {
                // Update the handle in the database
                match crate::oauth::db::update_token_handle(&app_state.db, &self.did, &handle_str).await {
                    Ok(_) => {
                        info!("Updated handle for DID {}: {}", self.did, handle_str);
                    }
                    Err(err) => {
                        error!("Failed to update handle in database: {:?}", err);
                        return Err(err);
                    }
                }
            } else {
                debug!("Handle for DID {} already up to date: {}", self.did, handle_str);
            }
        } else {
            debug!("No handle found in profile data for DID: {}", self.did);
        }

        Ok(())
    }
}
