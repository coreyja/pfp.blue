use std::sync::Arc;

use atrium_api::types::string::Did;
use atrium_xrpc_client::reqwest::ReqwestClient;
use color_eyre::eyre::eyre;
use tracing::{error, info};

use crate::{
    did::{extract_pds_from_document, resolve_did_to_document},
    oauth::OAuthTokenSet,
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
}

/// Extract profile information from Bluesky profile data
pub fn extract_profile_info(profile_data: &serde_json::Value) -> ProfileDataParams {
    let mut params = ProfileDataParams {
        display_name: None,
        avatar: None,
        description: None,
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
    todo!()
}
