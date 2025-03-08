use cja::jobs::Job;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{oauth::{self, OAuthTokenSet, create_dpop_proof_with_ath}, state::AppState};

// This implements the Jobs struct required by the cja job worker
cja::impl_job_registry!(
    AppState,
    NoopJob,
    UpdateProfileHandleJob,
    UpdateProfilePictureProgressJob
);

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

        // First, resolve the DID document to find PDS endpoint
        let xrpc_client = std::sync::Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
            "https://bsky.social",
        ));
        
        // Convert string DID to DID object
        let did = match atrium_api::types::string::Did::new(self.did.clone()) {
            Ok(did) => did,
            Err(err) => {
                error!("Invalid DID format: {:?}", err);
                return Err(eyre!("Invalid DID format: {}", err));
            }
        };
        
        // Resolve DID to document
        let did_document = match crate::did::resolve_did_to_document(&did, xrpc_client).await {
            Ok(doc) => doc,
            Err(err) => {
                error!("Failed to resolve DID document: {:?}", err);
                return Err(eyre!("Failed to resolve DID document: {}", err));
            }
        };
        
        // Find the PDS service endpoint
        let services = match did_document.service.as_ref() {
            Some(services) => services,
            None => {
                error!("No service endpoints found in DID document");
                return Err(eyre!("No service endpoints found in DID document"));
            }
        };

        let pds_service = match services.iter().find(|s| s.id == "#atproto_pds") {
            Some(service) => service,
            None => {
                error!("No ATProto PDS service endpoint found in DID document");
                return Err(eyre!("No ATProto PDS service endpoint found in DID document"));
            }
        };

        let pds_endpoint = &pds_service.service_endpoint;
        info!("Found PDS endpoint for DID {}: {}", self.did, pds_endpoint);

        // Construct the full URL to the PDS endpoint
        let get_record_url = format!("{}/xrpc/com.atproto.repo.getRecord", pds_endpoint);
        
        // Access token hash is required for requests to PDS
        
        // Start with no nonce and handle any in the error response
        // Create a DPoP proof for this API call using the PDS endpoint (no nonce initially)
        // Include access token hash (ath)
        let dpop_proof = match create_dpop_proof_with_ath(
            &app_state.bsky_oauth,
            "GET",
            &get_record_url,
            None,
            &token.access_token,
        ) {
            Ok(proof) => proof,
            Err(err) => {
                error!("Failed to create DPoP proof for profile job: {:?}", err);
                return Err(err);
            }
        };

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
                    let new_dpop_proof = match create_dpop_proof_with_ath(
                        &app_state.bsky_oauth,
                        "GET",
                        &get_record_url,
                        Some(new_nonce),
                        &token.access_token,
                    ) {
                        Ok(proof) => proof,
                        Err(err) => {
                            error!("Failed to create DPoP proof with new nonce: {:?}", err);
                            return Err(err);
                        }
                    };
                    
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
        let response = match response_result
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

            error!(
                "Failed to fetch profile for {}: {} - {}",
                &self.did, status, error_text
            );
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
                match crate::oauth::db::update_token_handle(&app_state.db, &self.did, &handle_str)
                    .await
                {
                    Ok(_) => {
                        info!("Updated handle for DID {}: {}", self.did, handle_str);
                    }
                    Err(err) => {
                        error!("Failed to update handle in database: {:?}", err);
                        return Err(err);
                    }
                }
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

/// Job to update a user's profile picture with progress visualization
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateProfilePictureProgressJob {
    /// The token ID to process
    pub token_id: uuid::Uuid,
}

impl UpdateProfilePictureProgressJob {
    /// Create a new job from a token ID
    pub fn new(token_id: uuid::Uuid) -> Self {
        Self { token_id }
    }
}

#[async_trait::async_trait]
impl Job<AppState> for UpdateProfilePictureProgressJob {
    const NAME: &'static str = "UpdateProfilePictureProgressJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        use color_eyre::eyre::eyre;
        use tracing::{debug, error, info};

        // First, get the token from the database
        let token = match sqlx::query!(
            r#"
            SELECT did, access_token, token_type, handle, expires_at, 
                   refresh_token, scope, dpop_jkt, user_id
            FROM oauth_tokens
            WHERE id = $1
            "#,
            self.token_id
        )
        .fetch_optional(&app_state.db)
        .await?
        {
            Some(row) => crate::oauth::OAuthTokenSet {
                did: row.did,
                access_token: row.access_token,
                token_type: row.token_type,
                expires_at: row.expires_at as u64,
                refresh_token: row.refresh_token,
                scope: row.scope,
                handle: row.handle,
                dpop_jkt: row.dpop_jkt,
                user_id: Some(row.user_id),
            },
            None => {
                // No token found, can't proceed
                error!("No token found for ID {} in job", self.token_id);
                return Err(eyre!("No token found for ID"));
            }
        };

        // Get the progress settings for this token
        let progress = match crate::profile_progress::ProfilePictureProgress::get_by_token_id(
            &app_state.db,
            self.token_id,
        )
        .await?
        {
            Some(progress) => progress,
            None => {
                error!(
                    "No progress settings found for token ID {} in job",
                    self.token_id
                );
                return Err(eyre!("No progress settings found"));
            }
        };

        // Check if the feature is enabled
        if !progress.enabled {
            debug!(
                "Profile picture progress feature is disabled for token ID {}",
                self.token_id
            );
            return Ok(());
        }

        // Check if we have the original blob CID
        let original_blob_cid = match progress.original_blob_cid {
            Some(cid) => cid,
            None => {
                error!("No original blob CID found for token ID {}", self.token_id);
                return Err(eyre!("No original blob CID found"));
            }
        };

        // Extract progress fraction or percentage from handle
        let (numerator, denominator) = match &token.handle {
            Some(handle) => extract_progress_from_handle(handle).unwrap_or((0.0, 1.0)),
            None => {
                debug!(
                    "No handle found for token ID {}, defaulting to 0%",
                    self.token_id
                );
                (0.0, 1.0)
            }
        };

        // Calculate the progress percentage
        let progress_percentage = numerator / denominator;
        debug!(
            "Progress for token {}: {}/{} = {:.2}%",
            self.token_id,
            numerator,
            denominator,
            progress_percentage * 100.0
        );

        // Fetch the original profile picture
        let original_image_data =
            match crate::routes::bsky::fetch_blob_by_cid(&token.did, &original_blob_cid).await {
                Ok(data) => data,
                Err(err) => {
                    error!("Failed to fetch original profile picture: {:?}", err);
                    return Err(eyre!("Failed to fetch original profile picture: {}", err));
                }
            };

        // Generate the progress image
        let progress_image_data =
            match generate_progress_image(&original_image_data, progress_percentage).await {
                Ok(data) => {
                    info!(
                        "Successfully generated progress image for token ID {}",
                        self.token_id
                    );
                    data
                }
                Err(err) => {
                    error!("Failed to generate progress image: {:?}", err);
                    return Err(err);
                }
            };

        // Upload the new image to Bluesky
        match upload_image_to_bluesky(&app_state, &token, &progress_image_data).await {
            Ok(cid) => {
                info!(
                    "Successfully uploaded progress image to Bluesky with CID: {}",
                    cid
                );

                // Update profile with the new image
                match update_profile_with_image(&app_state, &token, &cid).await {
                    Ok(_) => {
                        info!(
                            "Successfully updated profile with progress image for token ID {}",
                            self.token_id
                        );
                    }
                    Err(err) => {
                        error!("Failed to update profile with progress image: {:?}", err);
                        return Err(err);
                    }
                }
            }
            Err(err) => {
                error!("Failed to upload progress image to Bluesky: {:?}", err);
                return Err(err);
            }
        }

        Ok(())
    }
}

/// Extract progress from handle
/// Supports formats like "X/Y" or "X%" or "X.Y%"
fn extract_progress_from_handle(handle: &str) -> Option<(f64, f64)> {
    use regex::Regex;

    // Try to match X/Y format
    let fraction_re = Regex::new(r"(\d+)/(\d+)").unwrap();
    if let Some(captures) = fraction_re.captures(handle) {
        if let (Ok(numerator), Ok(denominator)) =
            (captures[1].parse::<f64>(), captures[2].parse::<f64>())
        {
            if denominator > 0.0 {
                return Some((numerator, denominator));
            }
        }
    }

    // Try to match X% or X.Y% format
    let percentage_re = Regex::new(r"(\d+(?:\.\d+)?)%").unwrap();
    if let Some(captures) = percentage_re.captures(handle) {
        if let Ok(percentage) = captures[1].parse::<f64>() {
            // Convert percentage to fraction
            return Some((percentage, 100.0));
        }
    }

    None
}

/// Generate a new profile picture with progress visualization
async fn generate_progress_image(
    original_image_data: &[u8],
    progress: f64,
) -> cja::Result<Vec<u8>> {
    use color_eyre::eyre::eyre;
    use image::{ImageFormat, Rgba};
    use imageproc::drawing::{
        draw_filled_circle_mut, draw_filled_rect_mut, draw_hollow_circle_mut,
    };
    use imageproc::rect::Rect;
    use std::io::Cursor;

    debug!("Generating progress image");
    // Load the original image
    let img = match image::load_from_memory(original_image_data) {
        Ok(img) => img,
        Err(err) => return Err(eyre!("Failed to load image: {}", err)),
    };

    // Convert to RGBA if it's not already
    let mut img = img.to_rgba8();

    // Get dimensions
    let width = img.width();
    let height = img.height();
    let size = width.min(height);

    debug!("Image dimensions: {}x{} Size: {}", width, height, size);

    // Center coordinates
    let center_x = width / 2;
    let center_y = height / 2;

    // Radius of the progress circle (slightly smaller than the image)
    let radius = (size / 2) as i32 - 10;

    debug!("Radius: {}", radius);

    // Progress bar style
    let bar_width = 10;
    let bar_color = Rgba([52, 152, 219, 200]); // Semi-transparent blue
    let bg_color = Rgba([0, 0, 0, 100]); // Semi-transparent black
    let outline_color = Rgba([255, 255, 255, 170]); // Semi-transparent white

    // Add a semi-transparent overlay at the bottom for text
    let overlay_height = 30;
    let bottom_rect = Rect::at(0, (height - overlay_height) as i32).of_size(width, overlay_height);
    draw_filled_rect_mut(&mut img, bottom_rect, Rgba([0, 0, 0, 150]));

    debug!("Drew overlay for text");

    // Starting angle is -90 degrees (top center)
    let start_angle = -90.0_f64.to_radians();

    // Draw background circle first (full 360 degrees)
    for angle_deg in 0..360 {
        let angle = (angle_deg as f64).to_radians();
        let x = center_x as f32 + (radius as f32 * angle.cos() as f32);
        let y = center_y as f32 + (radius as f32 * angle.sin() as f32);

        draw_filled_circle_mut(&mut img, (x as i32, y as i32), bar_width / 2, bg_color);
    }

    debug!("Drew background circle");

    // Draw the progress arc
    for angle_deg in 0..=(progress * 360.0) as i32 {
        let angle = start_angle + (angle_deg as f64).to_radians();
        let x = center_x as f32 + (radius as f32 * angle.cos() as f32);
        let y = center_y as f32 + (radius as f32 * angle.sin() as f32);

        draw_filled_circle_mut(&mut img, (x as i32, y as i32), bar_width / 2, bar_color);
    }

    debug!("Drew progress arc");

    // Draw outline circle
    draw_hollow_circle_mut(
        &mut img,
        (center_x as i32, center_y as i32),
        radius,
        outline_color,
    );

    debug!("Drew outline circle");

    // Add a progress bar at the bottom
    let indicator_width = (width as f64 * progress) as u32;
    debug!("Indicator width: {}", indicator_width);
    let indicator_rect = Rect::at(0, (height - 5) as i32).of_size(indicator_width, 5);
    debug!("Indicator rect: {:?}", indicator_rect);
    draw_filled_rect_mut(&mut img, indicator_rect, bar_color);

    debug!("Drew progress bar");

    // Convert the image back to bytes
    let mut buffer = Vec::new();
    let mut cursor = Cursor::new(&mut buffer);
    match img.write_to(&mut cursor, ImageFormat::Png) {
        Ok(_) => Ok(buffer),
        Err(err) => Err(eyre!("Failed to encode image: {}", err)),
    }
}

/// Upload an image to Bluesky and return the CID
async fn upload_image_to_bluesky(
    app_state: &AppState,
    token: &OAuthTokenSet,
    image_data: &[u8],
) -> cja::Result<String> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // Create a reqwest client
    let client = reqwest::Client::new();

    // First, resolve the DID document to find PDS endpoint
    let xrpc_client = std::sync::Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
        "https://bsky.social",
    ));
    
    // Convert string DID to DID object
    let did = match atrium_api::types::string::Did::new(token.did.clone()) {
        Ok(did) => did,
        Err(err) => {
            error!("Invalid DID format: {:?}", err);
            return Err(eyre!("Invalid DID format: {}", err));
        }
    };
    
    // Resolve DID to document
    let did_document = match crate::did::resolve_did_to_document(&did, xrpc_client).await {
        Ok(doc) => doc,
        Err(err) => {
            error!("Failed to resolve DID document: {:?}", err);
            return Err(eyre!("Failed to resolve DID document: {}", err));
        }
    };
    
    // Find the PDS service endpoint
    let services = match did_document.service.as_ref() {
        Some(services) => services,
        None => {
            error!("No service endpoints found in DID document");
            return Err(eyre!("No service endpoints found in DID document"));
        }
    };

    let pds_service = match services.iter().find(|s| s.id == "#atproto_pds") {
        Some(service) => service,
        None => {
            error!("No ATProto PDS service endpoint found in DID document");
            return Err(eyre!("No ATProto PDS service endpoint found in DID document"));
        }
    };

    let pds_endpoint = &pds_service.service_endpoint;
    info!("Found PDS endpoint for upload: {}", pds_endpoint);

    // Create a multipart form with the image data - simplified to work with current reqwest version
    let part = reqwest::multipart::Part::bytes(image_data.to_vec()).file_name("profile.png");
    let form = reqwest::multipart::Form::new().part("file", part);

    // Construct the full URL to the PDS endpoint
    let upload_url = format!("{}/xrpc/com.atproto.repo.uploadBlob", pds_endpoint);
    
    // For uploadBlob, we'll try directly with no nonce first
    // and then handle any nonce in the error response
    
    // We need to pass the access token to create_dpop_proof to calculate ath (access token hash)
    let dpop_proof = create_dpop_proof_with_ath(
        &app_state.bsky_oauth,
        "POST",
        &upload_url,
        None,
        &token.access_token,
    )?;

    // Make the API request to upload the blob directly to the user's PDS
    let mut response_result = client
        .post(&upload_url)
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", dpop_proof)
        .multipart(form)
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
                    "POST",
                    &upload_url,
                    Some(new_nonce),
                    &token.access_token,
                )?;
                
                // Retry the request with the new nonce
                // Need to recreate the form since we can't clone it
                let new_part = reqwest::multipart::Part::bytes(image_data.to_vec()).file_name("profile.png");
                let new_form = reqwest::multipart::Form::new().part("file", new_part);
                
                info!("Retrying upload with new DPoP-Nonce");
                response_result = client
                    .post(&upload_url)
                    .header("Authorization", format!("DPoP {}", token.access_token))
                    .header("DPoP", new_dpop_proof)
                    .multipart(new_form)
                    .send()
                    .await;
            }
        }
    }
    
    // Unwrap the final result
    let response = response_result?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());

        error!("Failed to upload blob: {} - {}", status, error_text);
        return Err(eyre!("Failed to upload blob: {} - {}", status, error_text));
    }

    // Parse the response JSON
    let response_data = response.json::<serde_json::Value>().await?;

    // Extract the blob CID
    let blob_cid = if let Some(blob) = response_data.get("blob") {
        if let Some(cid) = blob.get("$link") {
            cid.as_str().map(|s| s.to_string())
        } else {
            None
        }
    } else {
        None
    };

    match blob_cid {
        Some(cid) => {
            info!("Successfully uploaded blob with CID: {}", cid);
            Ok(cid)
        }
        None => {
            error!(
                "Failed to extract blob CID from response: {:?}",
                response_data
            );
            Err(eyre!("Failed to extract blob CID from response"))
        }
    }
}

/// Update profile with a new image
async fn update_profile_with_image(
    app_state: &AppState,
    token: &OAuthTokenSet,
    blob_cid: &str,
) -> cja::Result<()> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // First, we need to get the current profile to avoid losing other fields
    let client = reqwest::Client::new();

    // First, resolve the DID document to find PDS endpoint
    let xrpc_client = std::sync::Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
        "https://bsky.social",
    ));
    
    // Convert string DID to DID object
    let did = match atrium_api::types::string::Did::new(token.did.clone()) {
        Ok(did) => did,
        Err(err) => {
            error!("Invalid DID format: {:?}", err);
            return Err(eyre!("Invalid DID format: {}", err));
        }
    };
    
    // Resolve DID to document
    let did_document = match crate::did::resolve_did_to_document(&did, xrpc_client).await {
        Ok(doc) => doc,
        Err(err) => {
            error!("Failed to resolve DID document: {:?}", err);
            return Err(eyre!("Failed to resolve DID document: {}", err));
        }
    };
    
    // Find the PDS service endpoint
    let services = match did_document.service.as_ref() {
        Some(services) => services,
        None => {
            error!("No service endpoints found in DID document");
            return Err(eyre!("No service endpoints found in DID document"));
        }
    };

    let pds_service = match services.iter().find(|s| s.id == "#atproto_pds") {
        Some(service) => service,
        None => {
            error!("No ATProto PDS service endpoint found in DID document");
            return Err(eyre!("No ATProto PDS service endpoint found in DID document"));
        }
    };

    let pds_endpoint = &pds_service.service_endpoint;
    info!("Found PDS endpoint for profile update: {}", pds_endpoint);

    // Construct the full URL to the PDS endpoint for getRecord
    let get_record_url = format!("{}/xrpc/com.atproto.repo.getRecord", pds_endpoint);

    // Start with no nonce and handle any in the error response
    // Create a DPoP proof for getting the profile with access token hash
    let get_dpop_proof = create_dpop_proof_with_ath(
        &app_state.bsky_oauth,
        "GET",
        &get_record_url,
        None,
        &token.access_token,
    )?;

    // Make the API request to get current profile directly from user's PDS
    let mut get_response_result = client
        .get(&get_record_url)
        .query(&[
            ("repo", &token.did),
            ("collection", &String::from("app.bsky.actor.profile")),
            ("rkey", &String::from("self")),
        ])
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", get_dpop_proof)
        .send()
        .await;
    
    // Handle nonce errors by trying again if needed
    if let Ok(response) = &get_response_result {
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
                )?;
                
                // Retry the request with the new nonce
                info!("Retrying profile retrieval with new DPoP-Nonce");
                get_response_result = client
                    .get(&get_record_url)
                    .query(&[
                        ("repo", &token.did),
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
    
    // Unwrap the final result
    let get_response = get_response_result?;

    if !get_response.status().is_success() {
        let status = get_response.status();
        let error_text = get_response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());

        error!("Failed to get profile: {} - {}", status, error_text);
        return Err(eyre!("Failed to get profile: {} - {}", status, error_text));
    }

    // Parse the response JSON
    let profile_data = get_response.json::<serde_json::Value>().await?;

    // Get the existing profile value
    let mut profile_value = if let Some(value) = profile_data.get("value") {
        value.clone()
    } else {
        // No profile found, create a new one
        serde_json::json!({})
    };

    // Ensure profile_value is a mutable object
    if let serde_json::Value::Object(ref mut obj) = profile_value {
        // Update the avatar field with the new blob CID
        obj.insert(
            "avatar".to_string(),
            serde_json::json!({
                "$type": "blob",
                "ref": {
                    "$link": blob_cid
                },
                "mimeType": "image/png"
            }),
        );
    } else {
        return Err(eyre!("Profile value is not an object"));
    }

    // Construct the full URL to the PDS endpoint for putRecord
    let put_record_url = format!("{}/xrpc/com.atproto.repo.putRecord", pds_endpoint);

    // Start with no nonce and handle any in the error response
    // Create a DPoP proof for updating the profile with access token hash
    let put_dpop_proof = create_dpop_proof_with_ath(
        &app_state.bsky_oauth,
        "POST",
        &put_record_url,
        None,
        &token.access_token,
    )?;

    // Create the request body
    let put_body = serde_json::json!({
        "repo": token.did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": profile_value
    });

    // Make the API request to update the profile directly on the user's PDS
    let mut put_response_result = client
        .post(&put_record_url)
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", put_dpop_proof)
        .json(&put_body)
        .send()
        .await;
    
    // Handle nonce errors by trying again if needed
    if let Ok(response) = &put_response_result {
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
                    "POST",
                    &put_record_url,
                    Some(new_nonce),
                    &token.access_token,
                )?;
                
                // Retry the request with the new nonce
                info!("Retrying profile update with new DPoP-Nonce");
                put_response_result = client
                    .post(&put_record_url)
                    .header("Authorization", format!("DPoP {}", token.access_token))
                    .header("DPoP", new_dpop_proof)
                    .json(&put_body)
                    .send()
                    .await;
            }
        }
    }
    
    // Unwrap the final result
    let put_response = put_response_result?;

    if !put_response.status().is_success() {
        let status = put_response.status();
        let error_text = put_response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());

        error!("Failed to update profile: {} - {}", status, error_text);
        return Err(eyre!(
            "Failed to update profile: {} - {}",
            status,
            error_text
        ));
    }

    info!(
        "Successfully updated profile with new image for DID: {}",
        token.did
    );
    Ok(())
}
