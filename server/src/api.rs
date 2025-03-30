use std::sync::Arc;

use atrium_api::types::string::Did;
use atrium_xrpc_client::reqwest::ReqwestClient;
use color_eyre::eyre::eyre;
use tracing::{error, info};

use crate::{
    did::{extract_pds_from_document, resolve_did_to_document},
    oauth::{create_dpop_proof_with_ath, OAuthTokenSet},
    state::AppState,
};

/// Profile avatar information extracted from profile data
pub struct ProfileAvatar {
    pub cid: String,
    pub mime_type: String,
    pub data: Option<Vec<u8>>,
}

/// Parameters for profile data extraction
pub struct ProfileDataParams {
    pub display_name: Option<String>,
    pub avatar: Option<ProfileAvatar>,
    pub description: Option<String>,
    #[allow(dead_code)]
    pub profile_data: Option<serde_json::Value>,
}

/// Extract profile information from Bluesky profile data
pub fn extract_profile_info(profile_data: &serde_json::Value) -> ProfileDataParams {
    let mut params = ProfileDataParams {
        display_name: None,
        avatar: None,
        description: None,
        profile_data: Some(profile_data.clone()),
    };

    // Extract profile information from the data
    if let Some(value) = profile_data.get("value") {
        // Extract display name
        if let Some(name) = value.get("displayName").and_then(|n| n.as_str()) {
            params.display_name = Some(name.to_string());
        }

        // We no longer need to extract handle separately

        // Extract description
        if let Some(desc) = value.get("description").and_then(|d| d.as_str()) {
            params.description = Some(desc.to_string());
        }

        // Extract avatar information
        if let Some(avatar) = value.get("avatar") {
            // Get blob CID
            let cid = if let Some(ref_obj) = avatar.get("ref") {
                ref_obj
                    .get("$link")
                    .and_then(|l| l.as_str())
                    .map(|link| link.to_string())
            } else {
                None
            };

            // Get mime type
            let mime_type = avatar
                .get("mimeType")
                .and_then(|m| m.as_str())
                .unwrap_or("image/jpeg")
                .to_string();

            // If we found both, create avatar object
            if let Some(cid) = cid {
                params.avatar = Some(ProfileAvatar {
                    cid,
                    mime_type,
                    data: None,
                });
            }
        }
    }

    params
}

/// Fetch profile information with avatar data loaded
pub async fn get_profile_with_avatar(
    did: &str,
    app_state: &AppState,
) -> cja::Result<ProfileDataParams> {
    // Fetch the profile data
    let profile_data = get_user_profile(did, None, app_state).await?;

    // Extract profile information
    let mut profile_info = extract_profile_info(&profile_data);

    // If we have an avatar, try to load its data
    if let Some(avatar) = &profile_info.avatar {
        // Fetch the avatar blob
        match crate::routes::bsky::fetch_blob_by_cid(did, &avatar.cid, app_state).await {
            Ok(blob_data) => {
                // Update the avatar with the loaded data
                profile_info.avatar = Some(ProfileAvatar {
                    cid: avatar.cid.clone(),
                    mime_type: avatar.mime_type.clone(),
                    data: Some(blob_data),
                });
            }
            Err(e) => {
                error!("Failed to fetch avatar blob: {}", e);
                // Keep the avatar without data
            }
        }
    }

    Ok(profile_info)
}

/// Makes an authenticated API request to a Bluesky endpoint with DPoP
pub async fn make_authenticated_request(
    method: &str,
    endpoint_url: &str,
    token: &OAuthTokenSet,
    app_state: &AppState,
    query_params: Option<Vec<(&str, &str)>>,
    json_body: Option<&serde_json::Value>,
) -> cja::Result<reqwest::Response> {
    let client = reqwest::Client::new();

    // Create a DPoP proof with access token hash
    let dpop_proof = create_dpop_proof_with_ath(
        &app_state.bsky_oauth,
        method,
        endpoint_url,
        None, // No initial nonce
        &token.access_token,
    )?;

    // Build the request based on method
    let mut req_builder = match method {
        "GET" => {
            let mut builder = client.get(endpoint_url);
            if let Some(params) = &query_params {
                builder = builder.query(params);
            }
            builder
        }
        "POST" => {
            let builder = client.post(endpoint_url);
            if let Some(body) = json_body {
                builder.json(body)
            } else {
                builder
            }
        }
        // Add other methods as needed
        _ => return Err(eyre!("Unsupported HTTP method: {}", method)),
    };

    // Add auth headers
    req_builder = req_builder
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", &dpop_proof);

    // Send the request
    let mut response_result = req_builder.send().await;

    // Handle 401 with DPoP nonce
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
                    method,
                    endpoint_url,
                    Some(new_nonce),
                    &token.access_token,
                )?;

                // Retry the request with the new nonce
                info!("Retrying request with new DPoP-Nonce");

                // Rebuild the request
                let mut retry_builder = match method {
                    "GET" => {
                        let mut builder = client.get(endpoint_url);
                        if let Some(params) = &query_params {
                            builder = builder.query(params);
                        }
                        builder
                    }
                    "POST" => {
                        let builder = client.post(endpoint_url);
                        if let Some(body) = json_body {
                            builder.json(body)
                        } else {
                            builder
                        }
                    }
                    _ => return Err(eyre!("Unsupported HTTP method: {}", method)),
                };

                retry_builder = retry_builder
                    .header("Authorization", format!("DPoP {}", token.access_token))
                    .header("DPoP", new_dpop_proof);

                response_result = retry_builder.send().await;
            }
        }
    }

    // Unwrap the final result
    let response = response_result?;

    // Check if request succeeded
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());

        error!("API request failed: {} - {}", status, error_text);
        return Err(eyre!("API request failed: {} - {}", status, error_text));
    }

    Ok(response)
}

/// Finds the Personal Data Server (PDS) endpoint for a user's DID
pub async fn find_pds_endpoint(did: &str, client: Arc<ReqwestClient>) -> cja::Result<String> {
    // Convert string DID to DID object
    let did_obj = Did::new(did.to_string()).map_err(|e| eyre!("Invalid DID format: {}", e))?;

    // Resolve DID to document
    let did_document = resolve_did_to_document(&did_obj, client).await?;

    // Find the PDS service endpoint
    let pds_service = extract_pds_from_document(&did_document)?;
    let pds_endpoint = &pds_service.service_endpoint;

    info!("Found PDS endpoint for DID {}: {}", did, pds_endpoint);
    Ok(pds_endpoint.clone())
}

/// Gets a user's profile from their PDS
pub async fn get_user_profile(
    did: &str,
    token: Option<&OAuthTokenSet>,
    app_state: &AppState,
) -> cja::Result<serde_json::Value> {
    let pds_endpoint = find_pds_endpoint(did, app_state.bsky_client.clone()).await?;

    // Construct the full URL to the PDS endpoint
    let get_record_url = format!("{}/xrpc/com.atproto.repo.getRecord", pds_endpoint);

    if let Some(token) = token {
        // Authenticated request - uses the token
        let response = make_authenticated_request(
            "GET",
            &get_record_url,
            token,
            app_state,
            Some(vec![
                ("repo", did),
                ("collection", "app.bsky.actor.profile"),
                ("rkey", "self"),
            ]),
            None,
        )
        .await?;

        let profile_data = response.json::<serde_json::Value>().await?;
        Ok(profile_data)
    } else {
        // Unauthenticated request - no token needed
        let client = reqwest::Client::new();

        let response = client
            .get(&get_record_url)
            .query(&[
                ("repo", did),
                ("collection", "app.bsky.actor.profile"),
                ("rkey", "self"),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            return Err(eyre!(
                "Failed to fetch user profile: {} - {}",
                status,
                error_text
            ));
        }

        // Parse the response JSON
        let profile_data = response.json::<serde_json::Value>().await?;
        Ok(profile_data)
    }
}

// Functions below were removed as they are not used anywhere in the codebase
// We can add them back when needed with proper implementations that match our error handling patterns
