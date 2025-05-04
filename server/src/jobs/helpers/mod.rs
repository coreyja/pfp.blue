use color_eyre::eyre::{eyre, Result, WrapErr};
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::prelude::*;

pub async fn get_original_profile_picture(
    app_state: &AppState,
    account: &Account,
) -> Result<Value> {
    todo!()
}

/// Helper function to resolve DID to PDS endpoint with improved error handling
async fn resolve_did_to_pds(did_str: &str) -> Result<String> {
    let xrpc_client = Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
        "https://bsky.social",
    ));

    // Convert string DID to DID object
    let did = atrium_api::types::string::Did::new(did_str.to_string())
        .map_err(|e| eyre!("Invalid DID format for {}: {}", did_str, e))?;

    // Resolve DID to document
    let did_document = crate::did::resolve_did_to_document(&did, xrpc_client)
        .await
        .wrap_err_with(|| format!("Failed to resolve DID document for {}", did_str))?;

    // Find the PDS service endpoint
    let services = did_document
        .service
        .as_ref()
        .ok_or_else(|| eyre!("No service endpoints found in DID document for {}", did_str))?;

    let pds_service = services
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .ok_or_else(|| {
            eyre!(
                "No ATProto PDS service endpoint found in DID document for {}",
                did_str
            )
        })?;

    Ok(pds_service.service_endpoint.clone())
}

use crate::{
    oauth::{create_dpop_proof_with_ath, OAuthTokenSet},
    state::AppState,
};

/// Helper function to find PDS endpoint for a user
pub async fn find_pds_endpoint(token: &OAuthTokenSet) -> cja::Result<String> {
    resolve_did_to_pds(&token.did).await
}

/// Extract progress from display name
/// Supports formats like "X/Y" or "X%" or "X.Y%"
pub fn extract_progress_from_display_name(display_name: &str) -> Option<(f64, f64)> {
    use regex::Regex;

    // These regex patterns are constants, so we can unwrap safely
    // For production code, we'd use once_cell or lazy_static to compile them once
    // Try to match X/Y format
    let fraction_re = Regex::new(r"(\d+)/(\d+)")
        .expect("Invalid fraction regex pattern - this should never happen");
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
    let percentage_re = Regex::new(r"(\d+(?:\.\d+)?)%")
        .expect("Invalid percentage regex pattern - this should never happen");
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
    use image::{ImageFormat, Rgba, RgbaImage};
    use std::f64::consts::PI;
    use std::io::Cursor;

    debug!("Generating progress image");

    // Load the original image
    let original_img =
        image::load_from_memory(original_image_data).wrap_err("Failed to load image")?;

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
    final_img
        .write_to(&mut cursor, ImageFormat::Png)
        .wrap_err("Failed to encode final image to PNG")?;

    Ok(buffer)
}

/// Upload an image to Bluesky and return the blob object
pub async fn upload_image_to_bluesky(
    app_state: &AppState,
    token: &OAuthTokenSet,
    image_data: &[u8],
) -> cja::Result<Value> {
    // Create a reqwest client
    let client = Client::new();

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

    // Find PDS endpoint using our helper function
    let pds_endpoint = resolve_did_to_pds(&token.did)
        .await
        .wrap_err_with(|| format!("Failed to find PDS endpoint for {}", token.did))?;

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
    let response = response_result.wrap_err("Network error when uploading image to Bluesky")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .wrap_err("Failed to read error response")
            .unwrap_or_else(|e| format!("Failed to read error response: {}", e));

        error!("Failed to upload blob: {} - {}", status, error_text);
        return Err(eyre!("Failed to upload blob: {} - {}", status, error_text));
    }

    // Parse the response JSON
    let response_data = response.json::<Value>().await?;

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
    original_blob_object: Value,
) -> cja::Result<()> {
    // Create a reqwest client
    let client = Client::new();

    // Find PDS endpoint for this user
    let pds_endpoint = find_pds_endpoint(token)
        .await
        .wrap_err_with(|| format!("Failed to find PDS endpoint for {}", token.did))?;

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
    let put_response =
        put_response_result.wrap_err("Network error when saving original profile picture")?;

    if !put_response.status().is_success() {
        let status = put_response.status();
        let error_text = put_response
            .text()
            .await
            .wrap_err("Failed to read error response")
            .unwrap_or_else(|e| format!("Failed to read error response: {}", e));

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

/// Update profile with a new image
pub async fn update_profile_with_image(
    app_state: &AppState,
    token: &OAuthTokenSet,
    blob_object: Value,
) -> cja::Result<()> {
    // First, we need to get the current profile to avoid losing other fields
    let client = Client::new();

    // Find PDS endpoint using our helper function
    let pds_endpoint = resolve_did_to_pds(&token.did)
        .await
        .wrap_err_with(|| format!("Failed to find PDS endpoint for {}", token.did))?;

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
    let get_response = get_response_result.wrap_err("Network error when retrieving profile")?;

    if !get_response.status().is_success() {
        let status = get_response.status();
        let error_text = get_response
            .text()
            .await
            .wrap_err("Failed to read error response")
            .unwrap_or_else(|e| format!("Failed to read error response: {}", e));

        error!("Failed to get profile: {} - {}", status, error_text);
        return Err(eyre!("Failed to get profile: {} - {}", status, error_text));
    }

    // Parse the response JSON
    let profile_data = get_response.json::<Value>().await?;

    // Get the existing profile value
    let mut profile_value = if let Some(value) = profile_data.get("value") {
        value.clone()
    } else {
        // No profile found, create a new one
        serde_json::json!({})
    };

    // Ensure profile_value is a mutable object
    if let Value::Object(ref mut obj) = profile_value {
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
    let put_response =
        put_response_result.wrap_err("Network error when updating profile with new image")?;

    if !put_response.status().is_success() {
        let status = put_response.status();
        let error_text = put_response
            .text()
            .await
            .wrap_err("Failed to read error response")
            .unwrap_or_else(|e| format!("Failed to read error response: {}", e));

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
