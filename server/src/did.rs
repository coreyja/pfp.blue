use std::env;
use std::sync::Arc;

use atrium_api::{
    did_doc::{DidDocument, Service},
    types::string::{Did, Handle},
};
use atrium_common::resolver::Resolver;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig},
    handle::{AppViewHandleResolver, AppViewHandleResolverConfig},
};
use atrium_xrpc_client::reqwest::ReqwestClient;
use color_eyre::eyre::{eyre, WrapErr};
use tracing::info;

/// Resolves a Bluesky handle to its DID
pub async fn resolve_handle_to_did(
    handle: &Handle,
    client: Arc<ReqwestClient>,
) -> cja::Result<Did> {
    let appview_url = env::var("APPVIEW_URL").unwrap_or_else(|_| "https://bsky.social".to_string());
    let config = AppViewHandleResolverConfig {
        service_url: appview_url,
        http_client: client.clone(),
    };
    let resolver = AppViewHandleResolver::new(config);
    let identity = resolver.resolve(handle).await?;
    Ok(identity)
}

/// Resolves a string that might be either a DID or handle to a DID
pub async fn resolve_did_or_handle(
    did_or_handle: &str,
    client: Arc<ReqwestClient>,
) -> cja::Result<Did> {
    // Check if the input is a handle or a DID
    if did_or_handle.starts_with("did:") {
        // It's already a DID, validate and convert
        atrium_api::types::string::Did::new(did_or_handle.to_string())
            .map_err(|e| eyre!("Invalid DID format for {}: {}", did_or_handle, e))
    } else {
        // It's a handle, try to resolve it to a DID
        let handle = atrium_api::types::string::Handle::new(did_or_handle.to_string())
            .map_err(|e| eyre!("Invalid handle format for {}: {}", did_or_handle, e))?;

        info!("Resolving handle {} to DID", did_or_handle);
        resolve_handle_to_did(&handle, client).await
    }
}

/// Gets the configured PLC directory URL
pub fn get_plc_directory_url() -> String {
    // Make sure the URL doesn't have a trailing slash for consistency
    let url = env::var("PLC_DIRECTORY_URL").unwrap_or_else(|_| "https://plc.directory".to_string());
    url.trim_end_matches('/').to_string()
}

/// Resolves a DID to its full DID document
pub async fn resolve_did_to_document(
    did: &Did,
    client: Arc<ReqwestClient>,
) -> cja::Result<DidDocument> {
    let plc_directory_url = get_plc_directory_url();
    info!(
        "Attempting to resolve DID document for {} via PLC directory at {}",
        did.as_str(),
        plc_directory_url
    );

    let config = CommonDidResolverConfig {
        http_client: client.clone(),
        plc_directory_url,
    };
    let resolver = CommonDidResolver::new(config);

    let resolve_result = resolver.resolve(did).await;

    // Handle the normal case
    let document = resolve_result
        .wrap_err_with(|| format!("Failed to resolve DID document for {}", did.as_str()))?;
    info!("Successfully resolved DID document for {}", did.as_str());
    Ok(document)
}

/// Helper to extract PDS Service from a DID document
pub fn extract_pds_from_document(document: &DidDocument) -> cja::Result<&Service> {
    let services = document
        .service
        .as_ref()
        .ok_or_else(|| eyre!("No service endpoint found"))?;

    services
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .ok_or_else(|| eyre!("No ATProto PDS service endpoint found"))
}


