use cja::jobs::Job;
use color_eyre::eyre::eyre;
use color_eyre::eyre::Context as _;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    oauth::{create_dpop_proof_with_ath, OAuthTokenSet},
    state::AppState,
};

/// Job to update a user's profile information (display name and handle) in the database
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateProfileInfoJob {
    /// The DID of the user - only thing we need to look up the token in the DB
    pub did: String,
}

impl UpdateProfileInfoJob {
    /// Create a new job from an OAuthTokenSet
    pub fn from_token(token: &OAuthTokenSet) -> Self {
        Self {
            did: token.did.clone(),
        }
    }
}

#[async_trait::async_trait]
impl Job<AppState> for UpdateProfileInfoJob {
    const NAME: &'static str = "UpdateProfileInfoJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        // First, get the current token from the database with decryption
        let token = crate::oauth::get_valid_token_by_did(&self.did, &app_state)
            .await
            .wrap_err_with(|| format!("Error retrieving token for DID {}", self.did))?;

        let client = reqwest::Client::new();

        // First, resolve the DID document to find PDS endpoint
        let xrpc_client = std::sync::Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
            "https://bsky.social",
        ));

        // Convert string DID to DID object
        let did = atrium_api::types::string::Did::new(self.did.clone())
            .map_err(|e| eyre!("Invalid DID format: {}", e))?;

        // Resolve DID to document
        let did_document = crate::did::resolve_did_to_document(&did, xrpc_client)
            .await
            .wrap_err_with(|| format!("Failed to resolve DID document for {}", self.did))?;

        // Find the PDS service endpoint
        let services = did_document
            .service
            .as_ref()
            .ok_or_else(|| eyre!("No service endpoints found in DID document"))?;

        let pds_service = services
            .iter()
            .find(|s| s.id == "#atproto_pds")
            .ok_or_else(|| eyre!("No ATProto PDS service endpoint found in DID document"))?;

        let pds_endpoint = &pds_service.service_endpoint;
        info!("Found PDS endpoint for DID {}: {}", self.did, pds_endpoint);

        // Construct the full URL to the PDS endpoint
        let get_record_url = format!("{}/xrpc/com.atproto.repo.getRecord", pds_endpoint);

        // Access token hash is required for requests to PDS

        // Start with no nonce and handle any in the error response
        // Create a DPoP proof for this API call using the PDS endpoint (no nonce initially)
        // Include access token hash (ath)
        let dpop_proof = create_dpop_proof_with_ath(
            &app_state.bsky_oauth,
            "GET",
            &get_record_url,
            None,
            &token.access_token,
        )
        .wrap_err_with(|| {
            format!(
                "Failed to create DPoP proof for profile job for DID {}",
                self.did
            )
        })?;

        // Make the API request to get user profile directly from their PDS
        let mut response_result = client
            .get(&get_record_url)
            .query(&[
                ("repo", &self.did),
                ("collection", &String::from("app.bsky.actor.profile")),
                ("rkey", &String::from("self")),
            ])
            .header("Authorization", format!("DPoP {}", token.access_token))
            .header("DPoP", dpop_proof)
            .send()
            .await;

        // Handle nonce errors by trying again if needed
        if let Ok(response) = &response_result {
            if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                // Check if there's a DPoP-Nonce in the error response
                if let Some(new_nonce) = response
                    .headers()
                    .get("DPoP-Nonce")
                    .and_then(|h| h.to_str().ok())
                {
                    info!("Received new DPoP-Nonce in error response: {}", new_nonce);

                    // Create a new DPoP proof with the provided nonce and access token hash
                    let new_dpop_proof = create_dpop_proof_with_ath(
                        &app_state.bsky_oauth,
                        "GET",
                        &get_record_url,
                        Some(new_nonce),
                        &token.access_token,
                    )
                    .wrap_err_with(|| {
                        format!(
                            "Failed to create DPoP proof with new nonce for DID {}",
                            self.did
                        )
                    })?;

                    // Retry the request with the new nonce
                    info!("Retrying profile retrieval with new DPoP-Nonce");
                    response_result = client
                        .get(&get_record_url)
                        .query(&[
                            ("repo", &self.did),
                            ("collection", &String::from("app.bsky.actor.profile")),
                            ("rkey", &String::from("self")),
                        ])
                        .header("Authorization", format!("DPoP {}", token.access_token))
                        .header("DPoP", new_dpop_proof)
                        .send()
                        .await;
                }
            }
        }

        // Handle the final result
        let response = response_result.wrap_err("Network error when fetching profile")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .wrap_err("Failed to read error response")?;

            return Err(eyre!(
                "Failed to fetch profile: {} - {}",
                status,
                error_text
            ));
        }

        // Parse the response JSON
        let profile_data = response
            .json::<serde_json::Value>()
            .await
            .wrap_err_with(|| format!("Failed to parse profile response for DID {}", self.did))?;

        // Extract the display name and handle from the profile data
        let value = profile_data.get("value");

        // Extract the display name
        let extracted_display_name = if let Some(value) = value {
            if let Some(display_name_val) = value.get("displayName") {
                display_name_val.as_str().map(|s| s.to_string())
            } else {
                None
            }
        } else {
            None
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

        // If we found a display name in the profile, make sure it's updated in the database
        if let Some(display_name_str) = extracted_display_name {
            // Check if display name is different than what we have saved
            let should_update = match &token.display_name {
                Some(current_display_name) => current_display_name != &display_name_str,
                None => true, // No display name stored yet, need to update
            };

            if should_update {
                // Update the display name in the database
                crate::oauth::db::update_token_display_name(
                    &app_state.db,
                    &self.did,
                    &display_name_str,
                )
                .await
                .wrap_err_with(|| {
                    format!(
                        "Failed to update display name in database for DID {}",
                        self.did
                    )
                })?;

                info!(
                    "Updated display name for DID {}: {}",
                    self.did, display_name_str
                );
            } else {
                debug!(
                    "Display name for DID {} already up to date: {}",
                    self.did, display_name_str
                );
            }
        } else {
            debug!(
                "No display name found in profile data for DID: {}",
                self.did
            );
        }

        // If we found a handle in the profile, make sure it's updated in the database
        if let Some(handle_str) = extracted_handle {
            // Check if handle is different than what we have saved
            let should_update = match &token.handle {
                Some(current_handle) => current_handle != &handle_str,
                None => true, // No handle stored yet, need to update
            };

            if should_update {
                // Update the handle in the database
                crate::oauth::db::update_token_handle(&app_state.db, &self.did, &handle_str)
                    .await
                    .wrap_err_with(|| {
                        format!("Failed to update handle in database for DID {}", self.did)
                    })?;

                info!("Updated handle for DID {}: {}", self.did, handle_str);
            } else {
                debug!(
                    "Handle for DID {} already up to date: {}",
                    self.did, handle_str
                );
            }
        } else {
            debug!("No handle found in profile data for DID: {}", self.did);
        }

        Ok(())
    }
}
