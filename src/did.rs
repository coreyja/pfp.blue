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

async fn resolve_handle_to_did(handle: &str, client: Arc<ReqwestClient>) -> cja::Result<Did> {
    let handle = Handle::new(handle.to_string()).map_err(|_| eyre!("Invalid handle"))?;

    let config = AppViewHandleResolverConfig {
        service_url: "https://bsky.social".to_string(),
        http_client: client.clone(),
    };
    let resolver = AppViewHandleResolver::new(config);
    let identity = resolver.resolve(&handle).await?;
    Ok(identity)
}

pub const DEFAULT_PLC_DIRECTORY_URL: &str = "https://plc.directory/";

pub async fn resolve_handle_to_did_document(
    handle: &Handle,
    client: Arc<ReqwestClient>,
) -> cja::Result<DidDocument> {
    let did = resolve_handle_to_did(handle, client.clone()).await?;
    let document = resolve_did_to_document(&did, client.clone()).await?;

    if let Some(aka) = &document.also_known_as {
        if !aka.contains(&format!("at://{}", handle.as_str())) {
            return Err(atrium_identity::Error::DidDocument(format!(
                "did document for `{}` does not include the handle `{}`",
                did.as_str(),
                handle.as_str()
            ))
            .into());
        }
    }

    Ok(document)
}

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
