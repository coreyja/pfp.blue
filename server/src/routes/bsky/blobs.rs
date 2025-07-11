use color_eyre::eyre::{eyre, WrapErr};
use serde::Serialize;
use tracing::info;

/// Fetch a blob by its CID directly from the user's PDS
pub async fn fetch_blob_by_cid(
    did_or_handle: &str,
    cid: &str,
    app_state: &crate::state::AppState,
) -> cja::Result<Vec<u8>> {
    info!(
        "Fetching blob with CID: {} for DID/handle: {}",
        cid, did_or_handle
    );

    // Resolve the DID using our helper function
    let did_obj = crate::did::resolve_did_or_handle(did_or_handle, app_state.bsky_client.clone())
        .await
        .wrap_err_with(|| format!("Failed to resolve DID or handle: {did_or_handle}"))?;
    let did_str = did_obj.to_string();

    // Try to fetch the blob using our api module
    let client = reqwest::Client::new();
    let pds_endpoint = crate::api::find_pds_endpoint(&did_str, app_state.bsky_client.clone())
        .await
        .wrap_err_with(|| format!("Failed to find PDS endpoint for DID: {did_str}"))?;

    // Construct the getBlob URL using the PDS endpoint with the resolved DID
    #[derive(Serialize)]
    struct BlobUrlParams<'a> {
        did: &'a str,
        cid: &'a str,
    }

    let blob_params = BlobUrlParams { did: &did_str, cid };
    let query_string = serde_urlencoded::to_string(&blob_params)?;
    let blob_url = format!("{pds_endpoint}/xrpc/com.atproto.sync.getBlob?{query_string}");
    info!("Requesting blob from PDS: {}", blob_url);

    // Create a request for the blob
    let response = client
        .get(&blob_url)
        .send()
        .await
        .wrap_err_with(|| format!("Failed to send request to PDS for blob: {blob_url}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());

        info!("PDS request failed: {} - {}", status, error_text);

        // Try fallback to CDN as last resort using the resolved DID
        info!("Trying fallback to CDN...");
        let cdn_url = format!(
            "{}/img/avatar/plain/{}/{}@jpeg",
            app_state.avatar_cdn_url(),
            did_str,
            cid
        );

        match client.get(&cdn_url).send().await {
            Ok(cdn_response) => {
                if cdn_response.status().is_success() {
                    let blob_data = cdn_response
                        .bytes()
                        .await
                        .wrap_err("Failed to get response bytes from CDN fallback")?
                        .to_vec();
                    info!(
                        "Successfully retrieved blob from CDN: {} bytes",
                        blob_data.len()
                    );
                    Ok(blob_data)
                } else {
                    // Return the original PDS error
                    Err(eyre!(
                        "Failed to get blob from PDS: {} - {}",
                        status,
                        error_text
                    ))
                }
            }
            Err(e) => {
                // Return the original PDS error with fallback info
                Err(eyre!(
                    "Failed to get blob from PDS: {} - {}. CDN fallback also failed: {}",
                    status,
                    error_text,
                    e
                ))
            }
        }
    } else {
        // Success! Get the image data
        let blob_data = response
            .bytes()
            .await
            .wrap_err("Failed to get response bytes from PDS")?
            .to_vec();
        info!(
            "Successfully retrieved blob from PDS: {} bytes",
            blob_data.len()
        );
        Ok(blob_data)
    }
}
