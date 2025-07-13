use std::sync::Arc;

use atrium_api::types::string::Did;
use atrium_xrpc_client::reqwest::ReqwestClient;
use color_eyre::eyre::eyre;
use tracing::info;

use crate::did::{extract_pds_from_document, resolve_did_to_document};

/// Profile avatar information extracted from profile data
pub struct ProfileAvatar {
    pub cid: String,
    pub mime_type: String,
    // Allow dead code as this field is part of the API data structure but not currently used
    #[allow(dead_code)]
    pub data: Option<Vec<u8>>,
}

/// Parameters for profile data extraction
pub struct ProfileDataParams {
    pub display_name: Option<String>,
    pub avatar: Option<ProfileAvatar>,
    // Allow dead code as this field is part of the API data structure but not currently used
    #[allow(dead_code)]
    pub description: Option<String>,
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
