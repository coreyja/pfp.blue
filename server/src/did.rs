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
use tracing::{error, info};

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

    // In e2e tests, let's create a fake document when using fixture-user.test
    if resolve_result.is_err()
        && did.as_str() == "did:plc:abcdefg"
        && std::env::var("USE_FIXTURES").unwrap_or_default() == "1"
    {
        let err = resolve_result.unwrap_err();
        error!(
            "PLC resolution failed, but using fixture user, creating fake document: {}",
            err
        );
        return create_test_fixture_document(did);
    }

    // Handle the normal case
    let document = resolve_result
        .wrap_err_with(|| format!("Failed to resolve DID document for {}", did.as_str()))?;
    info!("Successfully resolved DID document for {}", did.as_str());
    Ok(document)
}

/// Creates a test fixture document for e2e testing
fn create_test_fixture_document(did: &Did) -> cja::Result<DidDocument> {
    let pds_url = std::env::var("PDS_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());

    // Create a minimal valid document for fixtures
    let doc = DidDocument {
        context: Some(vec!["https://w3id.org/did/v1".to_string()]),
        id: did.as_str().to_string(),
        also_known_as: Some(vec!["at://fixture-user.test".to_string()]),
        service: Some(vec![Service {
            id: "#atproto_pds".to_string(),
            service_endpoint: pds_url,
            r#type: "AtprotoPersonalDataServer".to_string(),
        }]),
        verification_method: Some(vec![]),
    };

    Ok(doc)
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

#[derive(serde::Deserialize)]
pub struct PDSMetadata {
    authorization_servers: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)] // Needed for deserialization from API responses
pub struct AuthServerMetadata {
    pub issuer: String,
    pub pushed_authorization_request_endpoint: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub scopes_supported: Vec<String>,
}

/// Converts a DID document to auth server metadata needed for OAuth flow
pub async fn document_to_auth_server_metadata(
    document: &DidDocument,
    _client: Arc<ReqwestClient>,
) -> cja::Result<AuthServerMetadata> {
    // If we're in fixture mode, shortcut with fixture data
    if std::env::var("USE_FIXTURES").unwrap_or_default() == "1" {
        return create_fixture_auth_server_metadata();
    }

    // Regular flow for production use
    let pds_service = extract_pds_from_document(document)?;
    let metadata = fetch_auth_server_metadata_from_pds(&pds_service.service_endpoint).await?;
    Ok(metadata)
}

/// Creates fixture auth server metadata for testing
fn create_fixture_auth_server_metadata() -> cja::Result<AuthServerMetadata> {
    let pds_url = std::env::var("PDS_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());

    info!(
        "Using fixture auth server metadata with PDS URL: {}",
        pds_url
    );

    // Return mock auth server metadata for fixture testing
    Ok(AuthServerMetadata {
        issuer: pds_url.clone(),
        pushed_authorization_request_endpoint: format!(
            "{}/xrpc/com.atproto.server.pushAuthorization",
            pds_url
        ),
        authorization_endpoint: format!("{}/xrpc/com.atproto.server.authorize", pds_url),
        token_endpoint: format!("{}/xrpc/com.atproto.server.getToken", pds_url),
        scopes_supported: vec![
            "read".to_string(),
            "write".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
    })
}

/// Fetches auth server metadata from a PDS endpoint
async fn fetch_auth_server_metadata_from_pds(
    pds_endpoint: &str,
) -> cja::Result<AuthServerMetadata> {
    // Step 1: Get the PDS metadata to find the auth server URL
    let pds_metadata_url = format!("{}/.well-known/oauth-protected-resource", pds_endpoint);
    info!("Fetching PDS metadata from URL: {}", pds_metadata_url);

    let pds_metadata = fetch_and_parse_json::<PDSMetadata>(&pds_metadata_url)
        .await
        .wrap_err_with(|| format!("Failed to get PDS metadata from {}", pds_metadata_url))?;

    // Step 2: Get the auth server metadata
    let auth_server_url = pds_metadata
        .authorization_servers
        .first()
        .ok_or_else(|| eyre!("No authorization server found"))?;

    let auth_server_metadata_url =
        format!("{}/.well-known/oauth-authorization-server", auth_server_url);

    info!(
        "Fetching auth server metadata from URL: {}",
        auth_server_metadata_url
    );

    let metadata = fetch_and_parse_json::<AuthServerMetadata>(&auth_server_metadata_url)
        .await
        .wrap_err_with(|| {
            format!(
                "Failed to get auth server metadata from {}",
                auth_server_metadata_url
            )
        })?;

    Ok(metadata)
}

/// Generic helper to fetch and parse JSON from a URL
pub async fn fetch_and_parse_json<T: serde::de::DeserializeOwned>(url: &str) -> cja::Result<T> {
    // Get the response
    let response = reqwest::get(url).await?;

    if !response.status().is_success() {
        error!("Failed to get data: HTTP {}", response.status());
        return Err(eyre!("Failed to get data: HTTP {}", response.status()))
            .wrap_err_with(|| format!("HTTP error {} when fetching {}", response.status(), url));
    }

    // Try to decode as JSON
    let response_text = response.text().await?;
    let result = serde_json::from_str::<T>(&response_text)
        .map_err(|e| {
            error!("Failed to decode JSON: {} from body: {}", e, response_text);
            e
        })
        .wrap_err_with(|| format!("Failed to decode JSON from {}", url))?;

    Ok(result)
}
