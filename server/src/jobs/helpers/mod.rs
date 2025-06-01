use atrium_api::agent::Agent;
use atrium_api::types::string::{Nsid, RecordKey};
use atrium_api::types::TryFromUnknown;
use color_eyre::eyre::{eyre, Result, WrapErr};
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, info};

use crate::prelude::*;

pub async fn get_original_profile_picture(
    app_state: &AppState,
    account: &Account,
) -> Result<Value> {
    let did = atrium_api::types::string::Did::new(account.did.clone())
        .map_err(|e| eyre!("Invalid DID format for {}: {}", account.did, e))?;
    let session = app_state.atrium.oauth.restore(&did).await?;
    let agent = Agent::new(session);

    let collection = Nsid::new("blue.pfp.unmodifiedPfp".to_string())
        .map_err(|e| eyre!("Invalid collection: {}", e))?;
    let rkey = RecordKey::new("self".to_string()).map_err(|e| eyre!("Invalid rkey: {}", e))?;
    let params = atrium_api::com::atproto::repo::get_record::ParametersData {
        collection,
        rkey,
        repo: did.into(),
        cid: None,
    };
    let resp = agent.api.com.atproto.repo.get_record(params.into()).await?;

    let value: Value = Value::try_from_unknown(resp.data.value)?;

    Ok(value)
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

use crate::{oauth::OAuthTokenSet, state::AppState};

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

    todo!()
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

    todo!()
}

/// Update profile with a new image
pub async fn update_profile_with_image(
    app_state: &AppState,
    token: &OAuthTokenSet,
    blob_object: Value,
) -> cja::Result<()> {
    todo!()
}
