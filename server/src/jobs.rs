use cja::jobs::Job;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    oauth::{create_dpop_proof_with_ath, OAuthTokenSet},
    state::AppState,
};

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
                return Err(eyre!(
                    "No ATProto PDS service endpoint found in DID document"
                ));
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
        let response = match response_result {
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
        let mut token = match sqlx::query!(
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

        // Check if the token is expired and try to refresh it if needed
        if token.is_expired() {
            info!(
                "Token for DID {} is expired, attempting to refresh",
                token.did
            );

            // Only try to refresh if we have a refresh token
            if let Some(refresh_token) = &token.refresh_token {
                // Get the client ID using the proper method from the app_state
                let client_id = app_state.client_id();

                // Try to get the token endpoint
                let token_endpoint = match crate::routes::bsky::get_token_endpoint_for_did(
                    &app_state.db,
                    &token.did,
                )
                .await
                {
                    Ok(Some(endpoint)) => endpoint,
                    _ => {
                        // Resolve the PDS endpoint for the token
                        let xrpc_client = std::sync::Arc::new(
                            atrium_xrpc_client::reqwest::ReqwestClient::new("https://bsky.social"),
                        );

                        match atrium_api::types::string::Did::new(token.did.clone()) {
                            Ok(did_obj) => {
                                match crate::did::resolve_did_to_document(&did_obj, xrpc_client)
                                    .await
                                {
                                    Ok(did_document) => {
                                        if let Some(services) = did_document.service.as_ref() {
                                            if let Some(pds_service) =
                                                services.iter().find(|s| s.id == "#atproto_pds")
                                            {
                                                let pds_endpoint = &pds_service.service_endpoint;
                                                let refresh_endpoint = format!(
                                                    "{}/xrpc/com.atproto.server.refreshSession",
                                                    pds_endpoint
                                                );
                                                info!(
                                                    "Resolved PDS endpoint for refresh: {}",
                                                    refresh_endpoint
                                                );
                                                refresh_endpoint
                                            } else {
                                                // Fallback to bsky.social if no PDS service found
                                                "https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string()
                                            }
                                        } else {
                                            // Fallback to bsky.social if no services found
                                            "https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string()
                                        }
                                    }
                                    Err(_) => {
                                        // Fallback to bsky.social on resolution error
                                        "https://bsky.social/xrpc/com.atproto.server.refreshSession"
                                            .to_string()
                                    }
                                }
                            }
                            Err(_) => {
                                // Fallback to bsky.social on DID parse error
                                "https://bsky.social/xrpc/com.atproto.server.refreshSession"
                                    .to_string()
                            }
                        }
                    }
                };

                // Get the latest DPoP nonce from the database
                let dpop_nonce =
                    match crate::oauth::db::get_latest_nonce(&app_state.db, &token.did).await {
                        Ok(nonce) => nonce,
                        Err(err) => {
                            error!("Failed to get DPoP nonce: {:?}", err);
                            None
                        }
                    };

                // Try to refresh the token
                match crate::oauth::refresh_token(
                    &app_state.bsky_oauth,
                    &token_endpoint,
                    &client_id,
                    refresh_token,
                    dpop_nonce.as_deref(),
                )
                .await
                {
                    Ok(token_response) => {
                        info!("Successfully refreshed token for DID {}", token.did);

                        // Create a new token set from the response
                        let new_token =
                            match crate::oauth::OAuthTokenSet::from_token_response_with_jwk(
                                &token_response,
                                token.did.clone(),
                                &app_state.bsky_oauth.public_key,
                            ) {
                                Ok(new_token) => new_token.with_handle_from(&token),
                                Err(err) => {
                                    error!("Failed to create token set with JWK: {:?}", err);
                                    // Fallback to standard token creation
                                    crate::oauth::OAuthTokenSet::from_token_response(
                                        token_response,
                                        token.did.clone(),
                                    )
                                    .with_handle_from(&token)
                                }
                            };

                        // Store the refreshed token
                        if let Err(err) =
                            crate::oauth::db::store_token(&app_state.db, &new_token).await
                        {
                            error!("Failed to store refreshed token: {:?}", err);
                            return Err(eyre!("Failed to store refreshed token"));
                        }

                        // Use the refreshed token for the rest of the job
                        token = new_token;
                    }
                    Err(err) => {
                        error!("Failed to refresh token: {:?}", err);
                        return Err(eyre!("Failed to refresh expired token: {}", err));
                    }
                }
            } else {
                error!(
                    "Token is expired but no refresh token is available for DID {}",
                    token.did
                );
                return Err(eyre!("Token is expired and no refresh token is available"));
            }
        }

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
        let original_image_data = match crate::routes::bsky::fetch_blob_by_cid(
            &token.did,
            &original_blob_cid,
            &app_state,
        )
        .await
        {
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
            Ok(blob_object) => {
                info!("Successfully uploaded progress image to Bluesky");

                // Update profile with the new image blob
                match update_profile_with_image(&app_state, &token, blob_object).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_progress_from_handle() {
        // Test fraction format
        let result = extract_progress_from_handle("user.bsky.app 3/4");
        assert_eq!(result, Some((3.0, 4.0)));

        let result = extract_progress_from_handle("42/100 progress");
        assert_eq!(result, Some((42.0, 100.0)));

        // Test percentage format
        let result = extract_progress_from_handle("user.bsky.app 75%");
        assert_eq!(result, Some((75.0, 100.0)));

        let result = extract_progress_from_handle("33.5% complete");
        assert_eq!(result, Some((33.5, 100.0)));

        // Test invalid inputs
        let result = extract_progress_from_handle("user.bsky.app");
        assert_eq!(result, None);

        let result = extract_progress_from_handle("0/0"); // Division by zero
        assert_eq!(result, None);
    }
}

/// Generate a new profile picture with progress visualization
pub async fn generate_progress_image(
    original_image_data: &[u8],
    progress: f64,
) -> cja::Result<Vec<u8>> {
    use color_eyre::eyre::eyre;
    use image::{ImageFormat, Rgba, RgbaImage};
    use imageproc::drawing::draw_filled_circle_mut;
    use std::f64::consts::PI;
    use std::io::Cursor;

    debug!("Generating progress image");

    // Load the original image
    let original_img = match image::load_from_memory(original_image_data) {
        Ok(img) => img,
        Err(err) => return Err(eyre!("Failed to load image: {}", err)),
    };

    // Get dimensions of the original image
    let width = original_img.width();
    let height = original_img.height();

    debug!("Original image dimensions: {}x{}", width, height);

    // Use a high-resolution intermediate image for better quality
    // Scale factor of 4 gives very smooth circles
    let scale_factor = 4;
    let large_width = width * scale_factor;
    let large_height = height * scale_factor;

    // Create a high-res version of the original image
    let large_img = original_img.resize_exact(
        large_width,
        large_height,
        image::imageops::FilterType::Lanczos3,
    );

    // Create a separate mask buffer at high resolution
    let mut mask = RgbaImage::new(large_width, large_height);

    // Center coordinates for the high-res image
    let center_x = large_width as f32 / 2.0;
    let center_y = large_height as f32 / 2.0;

    // Define the circle properties (scaled up)
    let outer_radius = ((width.min(height) as f32 / 2.0) - 10.0) * scale_factor as f32;
    let inner_radius = outer_radius - (10.0 * scale_factor as f32); // Line width of 10px
    let white_color = Rgba([255, 255, 255, 255]);

    debug!(
        "Drawing circle with radius {} - {}",
        inner_radius, outer_radius
    );

    // Our goal is to draw the arc starting from top (12 o'clock) and moving clockwise
    // First, determine the full angle we'll draw based on progress (0.0-1.0)
    let progress_angle = (2.0 * PI * progress) as f32;

    debug!(
        "Progress: {}, Progress angle: {} radians",
        progress, progress_angle
    );

    // Draw a filled arc by checking each pixel in the bounding box
    for y in 0..large_height {
        for x in 0..large_width {
            // Calculate the distance from center and angle
            let dx = x as f32 - center_x;
            let dy = y as f32 - center_y;
            let distance = (dx * dx + dy * dy).sqrt();

            // Only consider pixels in the ring area
            if distance >= inner_radius && distance <= outer_radius {
                // To determine if a pixel should be drawn, we need to find its angle
                // relative to the center, and see if it's within our progress arc

                // atan2(y,x) gives angles in this configuration:
                // - Range: -π to π
                // - 0: east (right)
                // - π/2: north (up) - NOTE: This is actually wrong! In atan2, π/2 is up in math coordinates,
                //   but in screen coordinates, y increases downward, so π/2 is actually down (south)
                // - π or -π: west (left)
                // - -π/2: south (down) - but in screen coordinates this is north/up

                // For screen coordinates with (0,0) at top-left:
                // - negative y is upward
                // - positive y is downward
                // So we need to flip the y for proper atan2 calculation
                let raw_angle = (-dy).atan2(dx); // Negate y to convert to math coordinates

                // Now raw_angle follows standard math conventions:
                // - 0: east (right/3 o'clock)
                // - π/2: north (up/12 o'clock)
                // - π or -π: west (left/9 o'clock)
                // - -π/2: south (down/6 o'clock)

                // Convert to 0 to 2π range
                let positive_angle = if raw_angle < 0.0 {
                    raw_angle + (2.0 * PI) as f32
                } else {
                    raw_angle
                };

                // To make 0 degrees at top (12 o'clock) and go clockwise:
                // 1. Subtract π/2 to place 0 at 12 o'clock (rotate left by 90°)
                // 2. Flip the direction by subtracting from 2π (to go clockwise)

                // Step 1: Rotate to make top 0° (subtract π/2)
                let top_centered = if positive_angle >= (PI / 2.0) as f32 {
                    positive_angle - (PI / 2.0) as f32
                } else {
                    positive_angle + (3.0 * PI / 2.0) as f32
                };

                // Step 2: Reverse direction to go clockwise
                let clockwise_angle = (2.0 * PI) as f32 - top_centered;

                // Now clockwise_angle has:
                // - 0: top (12 o'clock)
                // - π/2: right (3 o'clock)
                // - π: bottom (6 o'clock)
                // - 3π/2: left (9 o'clock)

                // Draw pixel if its angle is within our progress arc (0 to progress_angle)
                if clockwise_angle <= progress_angle {
                    mask.put_pixel(x, y, white_color);
                }
            }
        }
    }

    debug!("Drew progress arc mask");

    // Add a filled circle at the end of the progress arc
    if progress > 0.0 {
        // In our current system:
        // - 0: top (12 o'clock)
        // - π/2: right (3 o'clock)
        // - π: bottom (6 o'clock)
        // - 3π/2: left (9 o'clock)

        // For standard trigonometry:
        // - 0: right (3 o'clock)
        // - π/2: up (12 o'clock)
        // - π: left (9 o'clock)
        // - 3π/2: down (6 o'clock)

        // Convert our clockwise-from-top angle to standard angle
        // 1. Reverse direction: 2π - angle
        // 2. Rotate 90° counterclockwise: + π/2
        // 3. Normalize to 0-2π range

        // For Step 1: We already have our angle in clockwise-from-top format
        let clockwise_angle = progress_angle;

        // Step 2: Convert to counterclockwise-from-right (standard trig)
        // This is a two-step process:
        // a. Reverse direction (2π - angle)
        // b. Rotate 90° counterclockwise (add π/2)
        let reversed = (2.0 * PI) as f32 - clockwise_angle;
        let standard_angle = reversed + (PI / 2.0) as f32;

        // Step 3: Normalize to 0-2π range
        let normalized_angle = if standard_angle >= (2.0 * PI) as f32 {
            standard_angle - (2.0 * PI) as f32
        } else {
            standard_angle
        };

        // Use standard cos/sin with our normalized angle
        let end_x = center_x + outer_radius * normalized_angle.cos();
        let end_y = center_y + outer_radius * normalized_angle.sin();

        let circle_radius = (5.0 * scale_factor as f32) as i32;

        draw_filled_circle_mut(
            &mut mask,
            (end_x as i32, end_y as i32),
            circle_radius,
            white_color,
        );

        debug!("Added end cap to progress arc");
    }

    // Overlay the mask onto the original high-res image
    let mut large_result = large_img.to_rgba8();
    for y in 0..large_height {
        for x in 0..large_width {
            let mask_pixel = mask.get_pixel(x, y);

            // If mask pixel is white, set the result pixel to white
            if mask_pixel[3] > 0 {
                large_result.put_pixel(x, y, white_color);
            }
        }
    }

    // Resize back to original dimensions with high-quality downsampling
    let final_img = image::DynamicImage::ImageRgba8(large_result).resize_exact(
        width,
        height,
        image::imageops::FilterType::Lanczos3,
    );

    // Convert the final image to bytes
    let mut buffer = Vec::new();
    let mut cursor = Cursor::new(&mut buffer);
    match final_img.write_to(&mut cursor, ImageFormat::Png) {
        Ok(_) => Ok(buffer),
        Err(err) => Err(eyre!("Failed to encode image: {}", err)),
    }
}

/// Upload an image to Bluesky and return the blob object
async fn upload_image_to_bluesky(
    app_state: &AppState,
    token: &OAuthTokenSet,
    image_data: &[u8],
) -> cja::Result<serde_json::Value> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // Create a reqwest client
    let client = reqwest::Client::new();

    // Detect image format from magic bytes
    let image_mime_type = match infer::get(image_data) {
        Some(kind) => {
            // Check if it's a supported image type
            let mime = kind.mime_type();
            if mime == "image/png" || mime == "image/jpeg" {
                info!("Detected image format: {}", mime);
                mime
            } else {
                // Default to PNG for unsupported types
                info!("Unsupported image format: {}, defaulting to PNG", mime);
                "image/png"
            }
        }
        None => {
            // Default to PNG if we can't detect
            info!("Could not detect image format, defaulting to PNG");
            "image/png"
        }
    };

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
            return Err(eyre!(
                "No ATProto PDS service endpoint found in DID document"
            ));
        }
    };

    let pds_endpoint = &pds_service.service_endpoint;
    info!("Found PDS endpoint for upload: {}", pds_endpoint);

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

    info!("Uploading image with MIME type: {}", image_mime_type);

    // Make the API request to upload the blob directly to the user's PDS
    // Send the raw image data with the correct content type
    let mut response_result = client
        .post(&upload_url)
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", dpop_proof)
        .header("Content-Type", image_mime_type)
        .body(image_data.to_vec())
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
                info!("Retrying upload with new DPoP-Nonce");
                response_result = client
                    .post(&upload_url)
                    .header("Authorization", format!("DPoP {}", token.access_token))
                    .header("DPoP", new_dpop_proof)
                    .header("Content-Type", image_mime_type)
                    .body(image_data.to_vec())
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

    // Extract the entire blob object
    if let Some(blob) = response_data.get("blob").cloned() {
        // Log the blob information for debugging
        if let Some(blob_ref) = blob.get("ref") {
            if let Some(link) = blob_ref.get("$link").and_then(|l| l.as_str()) {
                info!("Successfully uploaded blob with CID: {}", link);
            }
        }
        Ok(blob)
    } else {
        error!(
            "Failed to extract blob object from response: {:?}",
            response_data
        );
        Err(eyre!("Failed to extract blob object from response"))
    }
}

/// Update profile with a new image
async fn update_profile_with_image(
    app_state: &AppState,
    token: &OAuthTokenSet,
    blob_object: serde_json::Value,
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
            return Err(eyre!(
                "No ATProto PDS service endpoint found in DID document"
            ));
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
        // Update the avatar field with the complete blob object
        obj.insert("avatar".to_string(), blob_object);
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
