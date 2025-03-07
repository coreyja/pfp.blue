use cja::jobs::Job;
use serde::{Deserialize, Serialize};

use crate::{oauth::OAuthTokenSet, state::AppState};
use sqlx::Row;

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
            "#,
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
            "#,
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
impl Job<AppState> for UpdateProfilePictureProgressJob {
    const NAME: &'static str = "UpdateProfilePictureProgressJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        use color_eyre::eyre::eyre;
        use tracing::{debug, error, info};

        // First, get the token from the database
        let token = match sqlx::query(
            r#"
            SELECT * FROM oauth_tokens
            WHERE id = $1
            "#,
        )
        .bind(self.token_id)
        .fetch_optional(&app_state.db)
        .await?
        {
            Some(row) => {
                let did: String = row.get("did");
                let access_token: String = row.get("access_token");
                let token_type: String = row.get("token_type");
                let handle: Option<String> = row.get("handle");

                crate::oauth::OAuthTokenSet {
                    did,
                    access_token,
                    token_type,
                    expires_at: row.get::<i64, _>("expires_at") as u64,
                    refresh_token: row.get("refresh_token"),
                    scope: row.get("scope"),
                    handle,
                    dpop_jkt: row.get("dpop_jkt"),
                    user_id: row.get("user_id"),
                }
            }
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
            None => (0.0, 1.0), // Default to 0% if no handle is found
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

    // Center coordinates
    let center_x = width / 2;
    let center_y = height / 2;

    // Radius of the progress circle (slightly smaller than the image)
    let radius = (size / 2) as i32 - 10;

    // Progress bar style
    let bar_width = 10;
    let bar_color = Rgba([52, 152, 219, 200]); // Semi-transparent blue
    let bg_color = Rgba([0, 0, 0, 100]); // Semi-transparent black
    let outline_color = Rgba([255, 255, 255, 170]); // Semi-transparent white

    // Add a semi-transparent overlay at the bottom for text
    let overlay_height = 30;
    let bottom_rect = Rect::at(0, (height - overlay_height) as i32).of_size(width, overlay_height);
    draw_filled_rect_mut(&mut img, bottom_rect, Rgba([0, 0, 0, 150]));

    // Starting angle is -90 degrees (top center)
    let start_angle = -90.0_f64.to_radians();

    // Draw background circle first (full 360 degrees)
    for angle_deg in 0..360 {
        let angle = (angle_deg as f64).to_radians();
        let x = center_x as f32 + (radius as f32 * angle.cos() as f32);
        let y = center_y as f32 + (radius as f32 * angle.sin() as f32);

        draw_filled_circle_mut(&mut img, (x as i32, y as i32), bar_width / 2, bg_color);
    }

    // Draw the progress arc
    for angle_deg in 0..=(progress * 360.0) as i32 {
        let angle = start_angle + (angle_deg as f64).to_radians();
        let x = center_x as f32 + (radius as f32 * angle.cos() as f32);
        let y = center_y as f32 + (radius as f32 * angle.sin() as f32);

        draw_filled_circle_mut(&mut img, (x as i32, y as i32), bar_width / 2, bar_color);
    }

    // Draw outline circle
    draw_hollow_circle_mut(
        &mut img,
        (center_x as i32, center_y as i32),
        radius,
        outline_color,
    );

    // Add a progress bar at the bottom
    let indicator_width = (width as f64 * progress) as u32;
    let indicator_rect = Rect::at(0, (height - 5) as i32).of_size(indicator_width, 5);
    draw_filled_rect_mut(&mut img, indicator_rect, bar_color);

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
    use tracing::{debug, error, info};

    // Create a reqwest client
    let client = reqwest::Client::new();

    // Create a multipart form with the image data - simplified to work with current reqwest version
    let part = reqwest::multipart::Part::bytes(image_data.to_vec())
        .file_name("profile.png");
    let form = reqwest::multipart::Form::new()
        .part("file", part);

    // Create a DPoP proof for the upload
    let dpop_proof = crate::oauth::create_dpop_proof(
        &app_state.bsky_oauth,
        "POST",
        "https://bsky.social/xrpc/com.atproto.repo.uploadBlob",
        None,
    )?;

    // Make the API request to upload the blob
    let response = client
        .post("https://bsky.social/xrpc/com.atproto.repo.uploadBlob")
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", dpop_proof)
        .multipart(form)
        .send()
        .await?;

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
    use tracing::{debug, error, info};

    // First, we need to get the current profile to avoid losing other fields
    let client = reqwest::Client::new();

    // Create a DPoP proof for getting the profile
    let get_dpop_proof = crate::oauth::create_dpop_proof(
        &app_state.bsky_oauth,
        "GET",
        "https://bsky.social/xrpc/com.atproto.repo.getRecord",
        None,
    )?;

    // Make the API request to get current profile
    let get_response = client
        .get("https://bsky.social/xrpc/com.atproto.repo.getRecord")
        .query(&[
            ("repo", &token.did),
            ("collection", &String::from("app.bsky.actor.profile")),
            ("rkey", &String::from("self")),
        ])
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", get_dpop_proof)
        .send()
        .await?;

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

    // Create a DPoP proof for updating the profile
    let put_dpop_proof = crate::oauth::create_dpop_proof(
        &app_state.bsky_oauth,
        "POST",
        "https://bsky.social/xrpc/com.atproto.repo.putRecord",
        None,
    )?;

    // Create the request body
    let put_body = serde_json::json!({
        "repo": token.did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": profile_value
    });

    // Make the API request to update the profile
    let put_response = client
        .post("https://bsky.social/xrpc/com.atproto.repo.putRecord")
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", put_dpop_proof)
        .json(&put_body)
        .send()
        .await?;

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
