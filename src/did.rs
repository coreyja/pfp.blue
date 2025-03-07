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
    let config = AppViewHandleResolverConfig {
        service_url: "https://bsky.social".to_string(),
        http_client: client.clone(),
    };
    let resolver = AppViewHandleResolver::new(config);
    let identity = resolver.resolve(handle).await?;
    Ok(identity)
}

pub const DEFAULT_PLC_DIRECTORY_URL: &str = "https://plc.directory/";

pub async fn resolve_did_to_document(
    did: &Did,
    client: Arc<ReqwestClient>,
) -> cja::Result<DidDocument> {
    let config = CommonDidResolverConfig {
        http_client: client.clone(),
        plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
    };
    let resolver = CommonDidResolver::new(config);
    let document = resolver.resolve(did).await?;
    Ok(document)
}

#[derive(serde::Deserialize)]
pub struct PDSMetadata {
    authorization_servers: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
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
    let pds_metadata = reqwest::get(pds_metadata_url)
        .await?
        .json::<PDSMetadata>()
        .await?;

    let auth_server_url = pds_metadata
        .authorization_servers
        .first()
        .ok_or_else(|| eyre!("No authorization server found"))?;
    let auth_server_metadata_url =
        format!("{}/.well-known/oauth-authorization-server", auth_server_url);

    let auth_server_metadata = reqwest::get(auth_server_metadata_url)
        .await?
        .json::<AuthServerMetadata>()
        .await?;

    Ok(auth_server_metadata)
}
