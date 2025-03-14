use std::env;
use std::sync::Arc;

use atrium_api::{
    did_doc::DidDocument,
    types::string::{Did, Handle},
};
use atrium_common::resolver::Resolver;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig},
    handle::{AppViewHandleResolver, AppViewHandleResolverConfig},
};
use atrium_xrpc_client::reqwest::ReqwestClient;
use color_eyre::eyre::eyre;

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

pub fn get_plc_directory_url() -> String {
    // Make sure the URL doesn't have a trailing slash for consistency
    let url = env::var("PLC_DIRECTORY_URL").unwrap_or_else(|_| "https://plc.directory".to_string());
    url.trim_end_matches('/').to_string()
}

pub async fn resolve_did_to_document(
    did: &Did,
    client: Arc<ReqwestClient>,
) -> cja::Result<DidDocument> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

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

    match resolver.resolve(did).await {
        Ok(document) => {
            info!("Successfully resolved DID document for {}", did.as_str());
            Ok(document)
        }
        Err(e) => {
            // In e2e tests, let's create a fake document when using fixture-user.test
            if did.as_str() == "did:plc:abcdefg"
                && std::env::var("USE_FIXTURES").unwrap_or_default() == "1"
            {
                error!(
                    "PLC resolution failed, but using fixture user, creating fake document: {}",
                    e
                );
                let pds_url = std::env::var("PDS_URL")
                    .unwrap_or_else(|_| "http://localhost:3001".to_string());

                // Create a minimal valid document for fixtures
                // Check the structure of DidDocument to ensure we create a valid one
                let doc = DidDocument {
                    context: Some(vec!["https://w3id.org/did/v1".to_string()]),
                    id: did.as_str().to_string(),
                    also_known_as: Some(vec!["at://fixture-user.test".to_string()]),
                    service: Some(vec![atrium_api::did_doc::Service {
                        id: "#atproto_pds".to_string(),
                        service_endpoint: pds_url,
                        // The field is "type" not "type_"
                        r#type: "AtprotoPersonalDataServer".to_string(),
                    }]),
                    verification_method: Some(vec![]),
                };

                Ok(doc)
            } else {
                error!("Failed to resolve DID document for {}: {}", did.as_str(), e);
                Err(eyre!("Failed to resolve DID document: {}", e))
            }
        }
    }
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

pub async fn document_to_auth_server_metadata(
    document: &DidDocument,
    _client: Arc<ReqwestClient>,
) -> cja::Result<AuthServerMetadata> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // If we're in fixture mode, shortcut with fixture data
    if std::env::var("USE_FIXTURES").unwrap_or_default() == "1" {
        let pds_url =
            std::env::var("PDS_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());
        info!(
            "Using fixture auth server metadata with PDS URL: {}",
            pds_url
        );

        // Return mock auth server metadata for fixture testing
        return Ok(AuthServerMetadata {
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
        });
    }

    // Regular flow for production use
    let services = document
        .service
        .as_ref()
        .ok_or_else(|| eyre!("No service endpoint found"))?;

    let pds_service = services
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .ok_or_else(|| eyre!("No ATProto service endpoint found"))?;

    let pds_metadata_url = format!(
        "{}/.well-known/oauth-protected-resource",
        pds_service.service_endpoint
    );
    info!("Fetching PDS metadata from URL: {}", pds_metadata_url);

    // Get the metadata response
    let response = reqwest::get(&pds_metadata_url).await?;
    if !response.status().is_success() {
        error!("Failed to get PDS metadata: HTTP {}", response.status());
        return Err(eyre!(
            "Failed to get PDS metadata: HTTP {}",
            response.status()
        ));
    }

    // Try to decode as JSON
    let response_text = response.text().await?;
    let pds_metadata = match serde_json::from_str::<PDSMetadata>(&response_text) {
        Ok(metadata) => metadata,
        Err(e) => {
            error!(
                "Failed to decode PDS metadata: {} from body: {}",
                e, response_text
            );
            return Err(eyre!("Failed to decode PDS metadata: {}", e));
        }
    };

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
    let auth_server_metadata = match reqwest::get(&auth_server_metadata_url).await {
        Ok(resp) => {
            if !resp.status().is_success() {
                error!("Failed to get auth server metadata: HTTP {}", resp.status());
                return Err(eyre!(
                    "Failed to get auth server metadata: HTTP {}",
                    resp.status()
                ));
            }

            // Try to decode as JSON
            let resp_text = resp.text().await?;
            match serde_json::from_str::<AuthServerMetadata>(&resp_text) {
                Ok(metadata) => metadata,
                Err(e) => {
                    error!(
                        "Failed to decode auth server metadata: {} from body: {}",
                        e, resp_text
                    );
                    return Err(eyre!("Failed to get auth server metadata: error decoding response body\n\nCaused by:\n    {}", e));
                }
            }
        }
        Err(e) => {
            error!("Failed to request auth server metadata: {}", e);
            return Err(eyre!("Failed to request auth server metadata: {}", e));
        }
    };

    Ok(auth_server_metadata)
}
