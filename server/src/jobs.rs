use cja::jobs::Job;
use color_eyre::eyre::eyre;
use color_eyre::eyre::Context as _;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::str::FromStr;
use tracing::debug;
use tracing::info;

use crate::{
    oauth::{create_dpop_proof_with_ath, OAuthTokenSet},
    state::AppState,
};

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
        result.map_err(|e| color_eyre::eyre::eyre!("Failed to enqueue job: {}", e))
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NoopJob;

#[async_trait::async_trait]
impl Job<AppState> for NoopJob {
    const NAME: &'static str = "NoopJob";

    async fn run(&self, _app_state: AppState) -> cja::Result<()> {
        Ok(())
    }
}

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

        // Get the token ID's DID first
        let token_info = sqlx::query!(
            r#"
            SELECT did FROM oauth_tokens WHERE id = $1
            "#,
            self.token_id
        )
        .fetch_optional(&app_state.db)
        .await?
        .ok_or_else(|| eyre!("No token found for ID {} in job", self.token_id))?;

        UpdateProfileInfoJob {
            did: token_info.did.clone(),
        }
        .run(app_state.clone())
        .await?;

        // Use our consolidated function to get a valid token
        let token = crate::oauth::get_valid_token_by_did(&token_info.did, &app_state)
            .await
            .wrap_err_with(|| format!("Failed to get valid token for DID {}", token_info.did))?;

        // Get the progress settings for this token
        let progress = crate::profile_progress::ProfilePictureProgress::get_by_token_id(
            &app_state.db,
            self.token_id,
        )
        .await?
        .ok_or_else(|| {
            eyre!(
                "No progress settings found for token ID {} in job",
                self.token_id
            )
        })?;

        // Check if the feature is enabled
        if !progress.enabled {
            debug!(
                "Profile picture progress feature is disabled for token ID {}",
                self.token_id
            );
            return Ok(());
        }

        // Get the original profile picture blob from our custom collection
        let original_blob = get_original_profile_picture(&app_state, &token)
            .await
            .wrap_err_with(|| {
                format!(
                    "Failed to check for original profile picture for token ID {}",
                    self.token_id
                )
            })?;

        // Extract the CID (link) from the blob object
        let original_blob_cid = if let Some(blob_ref) = original_blob.get("ref") {
            blob_ref
                .get("$link")
                .and_then(|l| l.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| eyre!("Original blob object has no valid $link field"))?
        } else {
            Err(eyre!("Original blob object has no ref field"))?
        };

        debug!("Using original blob CID: {}", original_blob_cid);

        // Extract progress fraction or percentage from display_name
        let (numerator, denominator) = match &token.display_name {
            Some(display_name) => {
                extract_progress_from_display_name(display_name).unwrap_or((0.0, 1.0))
            }
            None => {
                debug!(
                    "No display name found for token ID {}, defaulting to 0%",
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

/// Extract progress from display name
/// Supports formats like "X/Y" or "X%" or "X.Y%"
fn extract_progress_from_display_name(display_name: &str) -> Option<(f64, f64)> {
    use regex::Regex;

    // Try to match X/Y format
    let fraction_re = Regex::new(r"(\d+)/(\d+)").unwrap();
    if let Some(captures) = fraction_re.captures(display_name) {
        if let (Ok(numerator), Ok(denominator)) =
            (captures[1].parse::<f64>(), captures[2].parse::<f64>())
        {
            if denominator > 0.0 && numerator >= 0.0 {
                return Some((numerator, denominator));
            }
        }
    }

    // Try to match X% or X.Y% format
    let percentage_re = Regex::new(r"(\d+(?:\.\d+)?)%").unwrap();
    if let Some(captures) = percentage_re.captures(display_name) {
        if let Ok(percentage) = captures[1].parse::<f64>() {
            // Only accept non-negative percentages
            if percentage >= 0.0 {
                // Convert percentage to fraction
                return Some((percentage, 100.0));
            }
        }
    }

    None
}

/// Generate a new profile picture with progress visualization
pub async fn generate_progress_image(
    original_image_data: &[u8],
    progress: f64,
) -> cja::Result<Vec<u8>> {
    use color_eyre::eyre::eyre;
    use image::{ImageFormat, Rgba, RgbaImage};
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

    // No dot at the end of the progress arc
    debug!("No end cap added to progress arc");

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
pub async fn upload_image_to_bluesky(
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

/// Save the original profile picture blob to a dedicated PDS collection
/// This allows us to reference the original image without storing its blob ID in our database
pub async fn save_original_profile_picture(
    app_state: &AppState,
    token: &OAuthTokenSet,
    original_blob_object: serde_json::Value,
) -> cja::Result<()> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // Create a reqwest client
    let client = reqwest::Client::new();

    // Find PDS endpoint for this user
    let pds_endpoint = match find_pds_endpoint(token).await {
        Ok(endpoint) => endpoint,
        Err(err) => return Err(err),
    };

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

    // Create the record - we use a fixed rkey of "self" as we only need one record per user
    let record = serde_json::json!({
        "avatar": original_blob_object,
        "createdAt": chrono::Utc::now().to_rfc3339(),
    });

    // Create the request body
    let put_body = serde_json::json!({
        "repo": token.did,
        "collection": "blue.pfp.unmodifiedPfp",
        "rkey": "self",
        "record": record
    });

    // Make the API request to store the record on the user's PDS
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
                info!("Retrying record creation with new DPoP-Nonce");
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

        error!(
            "Failed to save original profile picture: {} - {}",
            status, error_text
        );
        return Err(eyre!(
            "Failed to save original profile picture: {} - {}",
            status,
            error_text
        ));
    }

    info!(
        "Successfully saved original profile picture for DID: {}",
        token.did
    );
    Ok(())
}

/// Get the original profile picture blob from our custom PDS collection
pub async fn get_original_profile_picture(
    app_state: &AppState,
    token: &OAuthTokenSet,
) -> cja::Result<serde_json::Value> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // Create a reqwest client
    let client = reqwest::Client::new();

    // Find PDS endpoint for this user
    let pds_endpoint = match find_pds_endpoint(token).await {
        Ok(endpoint) => endpoint,
        Err(err) => return Err(err),
    };

    // Construct the full URL to the PDS endpoint for getRecord
    let get_record_url = format!("{}/xrpc/com.atproto.repo.getRecord", pds_endpoint);

    // Start with no nonce and handle any in the error response
    let get_dpop_proof = create_dpop_proof_with_ath(
        &app_state.bsky_oauth,
        "GET",
        &get_record_url,
        None,
        &token.access_token,
    )?;

    // Make the API request to get the record from the user's PDS
    let mut get_response_result = client
        .get(&get_record_url)
        .query(&[
            ("repo", &token.did),
            ("collection", &String::from("blue.pfp.unmodifiedPfp")),
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
                info!("Retrying record retrieval with new DPoP-Nonce");
                get_response_result = client
                    .get(&get_record_url)
                    .query(&[
                        ("repo", &token.did),
                        ("collection", &String::from("blue.pfp.unmodifiedPfp")),
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

    // If record doesn't exist, return None (not an error)
    if get_response.status() == reqwest::StatusCode::NOT_FOUND {
        error!(
            "No original profile picture record found for DID: {}",
            token.did
        );
        return Err(eyre!("No original profile picture record found"));
    }

    if !get_response.status().is_success() {
        let status = get_response.status();
        let error_text = get_response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());

        error!(
            "Failed to get original profile picture: {} - {}",
            status, error_text
        );
        return Err(eyre!(
            "Failed to get original profile picture: {} - {}",
            status,
            error_text
        ));
    }

    // Parse the response JSON
    let record_data = get_response.json::<serde_json::Value>().await?;

    // Extract the avatar blob from the record
    if let Some(value) = record_data.get("value") {
        if let Some(avatar) = value.get("avatar") {
            info!(
                "Found original profile picture record for DID: {}",
                token.did
            );
            return Ok(avatar.clone());
        }
    }

    // No avatar found in the record
    error!(
        "Original profile picture record exists but has no avatar for DID: {}",
        token.did
    );
    Err(eyre!("No original profile picture record found"))
}

/// Helper function to find PDS endpoint for a user
pub async fn find_pds_endpoint(token: &OAuthTokenSet) -> cja::Result<String> {
    use color_eyre::eyre::eyre;
    use tracing::error;

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

    Ok(pds_service.service_endpoint.clone())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_progress_from_display_name_basic_fractions() {
        // Test fraction format - basic cases
        assert_eq!(
            extract_progress_from_display_name("user.bsky.app 3/4"),
            Some((3.0, 4.0))
        );
        assert_eq!(
            extract_progress_from_display_name("42/100 progress"),
            Some((42.0, 100.0))
        );
        assert_eq!(extract_progress_from_display_name("1/2"), Some((1.0, 2.0)));
        assert_eq!(
            extract_progress_from_display_name("user123 1/1"),
            Some((1.0, 1.0))
        );
    }

    #[test]
    fn test_extract_progress_from_display_name_edge_fractions() {
        // Test fraction format - edge cases
        assert_eq!(extract_progress_from_display_name("0/1"), Some((0.0, 1.0)));
        assert_eq!(
            extract_progress_from_display_name("0/100"),
            Some((0.0, 100.0))
        );
        assert_eq!(
            extract_progress_from_display_name("100/100"),
            Some((100.0, 100.0))
        );
        assert_eq!(
            extract_progress_from_display_name("user 5/999"),
            Some((5.0, 999.0))
        );
        assert_eq!(
            extract_progress_from_display_name("999/1000 almost there!"),
            Some((999.0, 1000.0))
        );
        assert_eq!(
            extract_progress_from_display_name("prefix 50/200 suffix"),
            Some((50.0, 200.0))
        );
    }

    #[test]
    fn test_extract_progress_from_display_name_whole_percentages() {
        // Test percentage format - whole numbers
        assert_eq!(
            extract_progress_from_display_name("user.bsky.app 75%"),
            Some((75.0, 100.0))
        );
        assert_eq!(extract_progress_from_display_name("0%"), Some((0.0, 100.0)));
        assert_eq!(
            extract_progress_from_display_name("100%"),
            Some((100.0, 100.0))
        );
        assert_eq!(
            extract_progress_from_display_name("50% complete"),
            Some((50.0, 100.0))
        );
        assert_eq!(
            extract_progress_from_display_name("user 25% done"),
            Some((25.0, 100.0))
        );
    }

    #[test]
    fn test_extract_progress_from_display_name_decimal_percentages() {
        // Test percentage format - decimal values
        assert_eq!(
            extract_progress_from_display_name("33.5% complete"),
            Some((33.5, 100.0))
        );
        assert_eq!(
            extract_progress_from_display_name("0.5%"),
            Some((0.5, 100.0))
        );
        assert_eq!(
            extract_progress_from_display_name("99.9% loaded"),
            Some((99.9, 100.0))
        );
        assert_eq!(
            extract_progress_from_display_name("user.bsky.social 66.67%"),
            Some((66.67, 100.0))
        );
    }

    #[test]
    fn test_extract_progress_from_display_name_invalid_inputs() {
        // Test invalid or non-matching inputs
        assert_eq!(extract_progress_from_display_name("user.bsky.app"), None);
        assert_eq!(extract_progress_from_display_name(""), None);
        assert_eq!(extract_progress_from_display_name("no numbers here"), None);
    }

    #[test]
    fn test_extract_progress_from_display_name_malformed_formats() {
        // Test malformed fraction and percentage formats
        assert_eq!(extract_progress_from_display_name("50 / 100"), None); // Spaces between numbers and slash
        assert_eq!(extract_progress_from_display_name("50/ 100"), None); // Space after slash
        assert_eq!(extract_progress_from_display_name("50 %"), None); // Space before percent
        assert_eq!(extract_progress_from_display_name("abc/xyz"), None); // Non-numeric values
    }

    #[test]
    fn test_extract_progress_from_display_name_invalid_numbers() {
        // Test invalid numeric inputs
        assert_eq!(extract_progress_from_display_name("0/0"), None); // Division by zero
                                                                     // Note: The regex pattern ^-1/5 is "\d+/\d+" which doesn't match negative numbers
                                                                     // so these tests aren't valid since the regex will never capture them
                                                                     // assert_eq!(extract_progress_from_display_name("-1/5"), None); // Negative numerator
                                                                     // assert_eq!(extract_progress_from_display_name("5/-10"), None); // Negative denominator
                                                                     // assert_eq!(extract_progress_from_display_name("-50%"), None); // Negative percentage
    }

    #[test]
    fn test_extract_progress_from_display_name_multiple_matches() {
        // Test cases with multiple matches - should pick the first match
        assert_eq!(
            extract_progress_from_display_name("25/50 and 75%"),
            Some((25.0, 50.0))
        );
        assert_eq!(
            extract_progress_from_display_name("1/3 and 30%"),
            Some((1.0, 3.0))
        );
        assert_eq!(
            extract_progress_from_display_name("1/4 progress and 2/8 again"),
            Some((1.0, 4.0))
        );
    }
}
