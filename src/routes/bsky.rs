use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use color_eyre::eyre::eyre;
use serde::Deserialize;
use std::time::SystemTime;
use tower_cookies::{Cookie, Cookies};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    oauth::{self, OAuthSession, OAuthTokenSet},
    state::AppState,
};

pub async fn client_metadata(state: State<AppState>) -> Json<serde_json::Value> {
    let fqdn = format!("{}://{}", state.protocol, state.domain);
    // Use the consistent client ID
    let metadata_url = state.client_id();
    let redirect_uri = state.redirect_uri();

    // Generate JWK for the client metadata
    let jwk = match oauth::generate_jwk(&state.bsky_oauth.public_key) {
        Ok(jwk) => jwk,
        Err(err) => {
            error!("Failed to generate JWK: {:?}", err);
            return Json(serde_json::json!({
                "error": "Failed to generate JWK"
            }));
        }
    };

    // Add the debug info for what we're sending
    info!("Sending client metadata with JWK: {:?}", jwk);

    // Craft the metadata according to OpenID Connect Dynamic Client Registration
    Json(serde_json::json!({
        "client_id": metadata_url,
        "application_type": "web",
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "atproto transition:generic",
        "response_types": ["code"],
        "redirect_uris": [redirect_uri],
        "dpop_bound_access_tokens": true,
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": {
            "keys": [jwk]
        },
        "client_name": "pfp.blue",
        "client_uri": fqdn,
        "logo_uri": format!("{fqdn}/static/logo.png"),
        "tos_uri": format!("{fqdn}/terms"),
        "policy_uri": format!("{fqdn}/privacy"),
    }))
}

#[derive(Deserialize)]
pub struct AuthParams {
    /// The user's Bluesky DID or Handle (will be resolved to DID if needed)
    pub did: String,
    /// Optional redirect URI for the OAuth flow
    pub redirect_uri: Option<String>,
    /// Optional state parameter to maintain state between requests
    pub state: Option<String>,
}

// Start the Bluesky OAuth flow
pub async fn authorize(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<AuthParams>,
) -> impl IntoResponse {
    // Use the helpers for consistent values
    let client_id = state.client_id();
    
    // Use the provided redirect_uri if any, or fall back to our default callback
    let redirect_uri = params.redirect_uri
        .unwrap_or_else(|| state.redirect_uri());
        
    // Log the input parameters for debugging
    info!("Authorize called with did: {}, redirect_uri: {:?}, state: {:?}", 
        params.did, redirect_uri, params.state);
    
    // Determine if input is a handle or DID
    let did_str = params.did.clone();
    let did = if did_str.starts_with("did:") {
        // Input is already a DID
        match atrium_api::types::string::Did::new(did_str.clone()) {
            Ok(did) => did,
            Err(_) => {
                error!("Invalid DID: {}", did_str);
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid DID".to_string(),
                )
                    .into_response();
            }
        }
    } else {
        // Input is a handle, resolve to DID
        match atrium_api::types::string::Handle::new(did_str.clone()) {
            Ok(handle) => {
                match crate::did::resolve_handle_to_did(&handle, state.bsky_client.clone()).await {
                    Ok(did) => did,
                    Err(err) => {
                        error!("Failed to resolve handle to DID: {:?}", err);
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("Failed to resolve handle to DID: {:?}", err),
                        )
                            .into_response();
                    }
                }
            },
            Err(_) => {
                error!("Invalid handle: {}", did_str);
                return (
                    StatusCode::BAD_REQUEST,
                    "Invalid handle".to_string(),
                )
                    .into_response();
            }
        }
    };
    
    let did_doc = match crate::did::resolve_did_to_document(&did, state.bsky_client.clone()).await {
        Ok(doc) => doc,
        Err(err) => {
            error!("Failed to resolve DID document: {:?}", err);
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to resolve DID document: {:?}", err),
            )
                .into_response();
        }
    };
    
    let auth_metadata = match crate::did::document_to_auth_server_metadata(&did_doc, state.bsky_client.clone()).await {
        Ok(metadata) => metadata,
        Err(err) => {
            error!("Failed to get auth server metadata: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get auth server metadata: {:?}", err),
            )
                .into_response();
        }
    };
    
    // Create and store the OAuth session
    let session = OAuthSession::new(
        did_str,
        params.state.clone(),
        auth_metadata.token_endpoint.clone(),
    );
    
    // Store the session in the database
    let session_id = match oauth::db::store_session(&state.db, &session).await {
        Ok(id) => id,
        Err(err) => {
            error!("Failed to store OAuth session: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to store session".to_string(),
            )
                .into_response();
        }
    };
    
    // Set a session cookie
    let mut cookie = Cookie::new("bsky_session_id", session_id.to_string());
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookies.add(cookie);
    
    // Build the authorization URL with state containing the session ID
    let state_param = session_id.to_string();
    
    // Get the code challenge from the session
    let code_challenge = session.code_challenge.as_deref().unwrap_or_default();
    
    // Build the URL with PKCE parameters
    let auth_url = format!(
        "{}?client_id={}&response_type=code&scope=atproto%20transition:generic&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
        auth_metadata.authorization_endpoint,
        client_id,
        redirect_uri,
        state_param,
        code_challenge
    );
    
    info!("Redirecting to auth URL: {}", auth_url);
    info!("Session ID: {}, Code Challenge: {}", session_id, code_challenge);
    Redirect::to(&auth_url).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Handle the callback from the Bluesky authorization server
/// Fetch a user's profile from Bluesky PDS
async fn fetch_user_profile(
    state: &AppState,
    did: &str,
    token: &OAuthTokenSet,
) -> cja::Result<serde_json::Value> {
    let client = reqwest::Client::new();
    
    // Create a DPoP proof for this API call
    let dpop_proof = oauth::create_dpop_proof(
        &state.bsky_oauth,
        "GET",
        &format!("https://bsky.social/xrpc/com.atproto.repo.getRecord"), // Use standard PDS URL
        None,
    )?;

    // Make the API request to get user profile
    let response = client
        .get("https://bsky.social/xrpc/com.atproto.repo.getRecord")
        .query(&[
            ("repo", did),
            ("collection", "app.bsky.actor.profile"),
            ("rkey", "self"),
        ])
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", dpop_proof)
        .send()
        .await?;
        
    // Check if we have a DPoP nonce in the response and store it
    if let Some(nonce_header) = response.headers().get("DPoP-Nonce") {
        if let Ok(nonce) = nonce_header.to_str() {
            tracing::debug!("Received DPoP-Nonce from profile request: {}", nonce);
            // We don't need to store it here since we're not retrying
        }
    }
    
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());
            
        return Err(eyre!("Failed to fetch user profile: {} - {}", status, error_text));
    }
    
    // Parse the response JSON
    let profile_data = response.json::<serde_json::Value>().await?;
    
    Ok(profile_data)
}

/// Fetch a blob from Bluesky PDS
async fn fetch_blob(
    state: &AppState,
    did: &str,
    token: &OAuthTokenSet,
    blob_ref: &str,
) -> cja::Result<Vec<u8>> {
    // The blob_ref is in the format "at://did:plc:abcdef/app.bsky.embed.images/12345"
    // We need to extract the CID for the API call
    
    info!("Fetching blob with ref: {}", blob_ref);
    
    // Check if this is a URI/link format
    if !blob_ref.starts_with("at://") {
        // If it's already a CID, use it directly
        return fetch_blob_by_cid(state, did, token, blob_ref).await;
    }
    
    // First get the record to find the actual blob CID
    let client = reqwest::Client::new();
    
    // The blob ref should be in format at://did/collection/rkey
    let blob_parts: Vec<&str> = blob_ref.trim_start_matches("at://").split('/').collect();
    
    if blob_parts.len() < 3 {
        return Err(eyre!("Invalid blob reference format: {}", blob_ref));
    }
    
    let repo = blob_parts[0];
    let collection = blob_parts[1];
    let rkey = blob_parts[2];
    
    info!("Parsed blob ref - repo: {}, collection: {}, rkey: {}", repo, collection, rkey);
    
    // Create a DPoP proof for this API call
    let dpop_proof = oauth::create_dpop_proof(
        &state.bsky_oauth,
        "GET",
        &format!("https://bsky.social/xrpc/com.atproto.repo.getRecord"), 
        None,
    )?;

    // First get the record to extract the blob CID
    let record_response = client
        .get("https://bsky.social/xrpc/com.atproto.repo.getRecord")
        .query(&[
            ("repo", repo),
            ("collection", collection),
            ("rkey", rkey),
        ])
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", dpop_proof)
        .send()
        .await?;
    
    let status = record_response.status();
    if !status.is_success() {
        let error_text = record_response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());
            
        return Err(eyre!("Failed to fetch record: {} - {}", status, error_text));
    }
    
    let record_data = record_response.json::<serde_json::Value>().await?;
    info!("Record data: {}", serde_json::to_string_pretty(&record_data).unwrap_or_default());
    
    // For images, the CID is usually in value.image.ref
    let cid = if let Some(value) = record_data.get("value") {
        if let Some(image) = value.get("image") {
            if let Some(image_ref) = image.get("ref") {
                image_ref.as_str().map(|s| s.to_string())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    
    match cid {
        Some(cid) => {
            info!("Extracted CID from record: {}", cid);
            fetch_blob_by_cid(state, did, token, &cid).await
        },
        None => {
            // Try a direct fetch if we couldn't extract the CID
            info!("Could not extract CID from record, trying direct fetch");
            fetch_blob_directly(state, did, token, blob_ref).await
        }
    }
}

/// Fetch a blob by its CID
async fn fetch_blob_by_cid(
    state: &AppState,
    did: &str,
    token: &OAuthTokenSet,
    cid: &str,
) -> cja::Result<Vec<u8>> {
    info!("Fetching blob with CID: {}", cid);
    let client = reqwest::Client::new();
    
    // Create a DPoP proof for this API call
    let dpop_proof = oauth::create_dpop_proof(
        &state.bsky_oauth,
        "GET",
        &format!("https://bsky.social/xrpc/com.atproto.sync.getBlob"),
        None,
    )?;

    // Make the API request to get the blob
    let response = client
        .get("https://bsky.social/xrpc/com.atproto.sync.getBlob")
        .query(&[
            ("did", did),
            ("cid", cid),
        ])
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", dpop_proof)
        .send()
        .await?;
        
    // Log response headers for debugging
    info!("Blob fetch response status: {}", response.status());
    for (name, value) in response.headers().iter() {
        if let Ok(value_str) = value.to_str() {
            info!("Header {}: {}", name, value_str);
        }
    }
    
    // Check if we have a DPoP nonce in the response
    if let Some(nonce_header) = response.headers().get("DPoP-Nonce") {
        if let Ok(nonce) = nonce_header.to_str() {
            info!("Received DPoP-Nonce from blob request: {}", nonce);
        }
    }
    
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());
            
        return Err(eyre!("Failed to fetch blob by CID: {} - {}", status, error_text));
    }
    
    // Get the binary blob data
    let blob_data = response.bytes().await?.to_vec();
    info!("Successfully retrieved blob: {} bytes", blob_data.len());
    
    Ok(blob_data)
}

/// Fetch a blob directly from an AT URL (fallback method)
async fn fetch_blob_directly(
    state: &AppState,
    did: &str,
    token: &OAuthTokenSet,
    blob_url: &str,
) -> cja::Result<Vec<u8>> {
    info!("Attempting direct blob fetch for: {}", blob_url);
    
    // For now just try a simple approach
    let client = reqwest::Client::new();
    
    // Create a DPoP proof for this API call
    let endpoint = "https://bsky.social/xrpc/com.atproto.sync.getBlob";
    let dpop_proof = oauth::create_dpop_proof(
        &state.bsky_oauth,
        "GET",
        endpoint,
        None,
    )?;
    
    // Try to access the blob directly
    let response = client
        .get(endpoint)
        .query(&[
            ("did", did),
            ("at", blob_url),
        ])
        .header("Authorization", format!("DPoP {}", token.access_token))
        .header("DPoP", dpop_proof)
        .send()
        .await?;
    
    info!("Direct blob fetch response status: {}", response.status());
    
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error response".to_string());
            
        return Err(eyre!("Failed direct blob fetch: {} - {}", status, error_text));
    }
    
    // Get the binary blob data
    let blob_data = response.bytes().await?.to_vec();
    info!("Successfully retrieved blob directly: {} bytes", blob_data.len());
    
    Ok(blob_data)
}

pub async fn callback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    // Use the consistent helpers
    let client_id = state.client_id();
    let redirect_uri = state.redirect_uri();
    
    // Log all parameters for debugging
    info!("Callback received: code: {:?}, state: {:?}, error: {:?}, error_description: {:?}",
        params.code, params.state, params.error, params.error_description);
        
    // Also log cookie info
    if let Some(session_cookie) = cookies.get("bsky_session_id") {
        info!("Found session cookie: {}", session_cookie.value());
    } else {
        info!("No session cookie found");
    }
    
    // If we have an error, display it
    if let Some(error) = params.error {
        let error_description = params.error_description.unwrap_or_else(|| "No error description provided".to_string());
        error!("OAuth error: {} - {}", error, error_description);
        
        return maud::html! {
            h1 { "Authentication Error" }
            p { "There was an error during authentication:" }
            p { "Error: " (error) }
            p { "Description: " (error_description) }
            p { "Debug Info:" }
            p { "Client ID: " (client_id) }
            p { "Redirect URI: " (redirect_uri) }
            p { 
                a href="/" { "Return to Home" }
            }
        }.into_response();
    }
    
    // Make sure we have a code
    let code = match params.code {
        Some(code) => code,
        None => {
            error!("No code parameter in callback");
            
            // Provide a more user-friendly response with debugging info
            return maud::html! {
                h1 { "Authentication Error" }
                p { "There was an error during the authorization process." }
                p { "The Bluesky server did not provide an authorization code in the callback." }
                p { "Debug Information:" }
                p { "State parameter: " (params.state.as_deref().unwrap_or("None")) }
                p { "Client ID: " (client_id) }
                p { "Redirect URI: " (redirect_uri) }
                p { 
                    a href="/" { "Return to Home" }
                }
                p {
                    a href="/login" { "Try Again" }
                }
            }.into_response();
        }
    };
    
    info!("Received code: {}, state: {:?}", code, params.state);
    
    // Get the session ID from the state parameter or the cookie
    let session_id = match params.state.as_ref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            cookies.get("bsky_session_id")
                .and_then(|c| Uuid::parse_str(c.value()).ok())
        }) {
        Some(id) => id,
        None => {
            error!("No valid session ID found in state or cookie");
            return (
                StatusCode::BAD_REQUEST,
                "No valid session found. Please try authenticating again.".to_string(),
            ).into_response();
        }
    };
    
    // Retrieve session data from the database
    let session = match oauth::db::get_session(&state.db, session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            error!("Session not found: {}", session_id);
            return (
                StatusCode::BAD_REQUEST,
                "Session not found. Please try authenticating again.".to_string(),
            ).into_response();
        }
        Err(err) => {
            error!("Failed to retrieve session: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve session data".to_string(),
            ).into_response();
        }
    };
    
    // Check if the session is expired
    if session.is_expired() {
        error!("Session expired: {}", session_id);
        return (
            StatusCode::BAD_REQUEST,
            "Session expired. Please try authenticating again.".to_string(),
        ).into_response();
    }
    
    // Get the code verifier from the session for PKCE
    let code_verifier = session.code_verifier.as_deref();
    
    // Exchange the code for an access token
    let mut attempts = 0;
    let mut last_error = None;
    let mut token_response = None;
    
    // Try up to 2 times - once with the stored nonce and once with a new nonce if needed
    while attempts < 2 && token_response.is_none() {
        match oauth::exchange_code_for_token(
            &state.bsky_oauth,
            &session.token_endpoint,
            &client_id,
            &code,
            &redirect_uri,
            code_verifier,
            session.dpop_nonce.as_deref(),  // Use the stored nonce if available
        ).await {
            Ok(response) => {
                token_response = Some(response);
            },
            Err(err) => {
                last_error = Some(err.to_string());
                
                // Check if the error contains a DPoP nonce error
                if last_error.as_ref().unwrap().contains("use_dpop_nonce") || 
                   last_error.as_ref().unwrap().contains("nonce mismatch") {
                    
                    // Try to extract the nonce from the error message
                    if let Some(nonce_start) = last_error.as_ref().unwrap().find("\"dpop_nonce\":\"") {
                        let nonce_substring = &last_error.as_ref().unwrap()[nonce_start + 14..];
                        if let Some(nonce_end) = nonce_substring.find('\"') {
                            let new_nonce = &nonce_substring[..nonce_end];
                            
                            // Save the new nonce in the database for this session
                            if let Err(e) = oauth::db::update_session_nonce(&state.db, session_id, new_nonce).await {
                                error!("Failed to update session nonce: {:?}", e);
                            } else {
                                // Update the session object with the new nonce
                                let mut updated_session = session.clone();
                                updated_session.dpop_nonce = Some(new_nonce.to_string());
                                
                                // Try again with the new session containing the updated nonce
                                attempts += 1;
                                continue;
                            }
                        }
                    }
                }
                
                // If we couldn't extract a nonce or it's not a nonce error, break
                break;
            }
        }
        
        attempts += 1;
    }
    
    let token_response = match token_response {
        Some(token) => token,
        None => {
            let error_msg = last_error.as_ref().unwrap_or(&"Unknown error".to_string()).clone();
            error!("Token exchange failed: {:?}", error_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to exchange authorization code for token: {:?}", error_msg),
            ).into_response();
        }
    };
    
    // Create a token set with JWK thumbprint
    let token_set = match OAuthTokenSet::from_token_response_with_jwk(
        &token_response, 
        session.did.clone(),
        &state.bsky_oauth.public_key
    ) {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to create token set with JWK: {:?}", err);
            // Fallback to standard token creation without JWK calculation
            OAuthTokenSet::from_token_response(token_response, session.did.clone())
        }
    };
    
    // Store the token in the database
    if let Err(err) = oauth::db::store_token(&state.db, &token_set).await {
        error!("Failed to store token: {:?}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to store access token".to_string(),
        ).into_response();
    }
    
    info!("Authentication successful for DID: {}", session.did);
    
    // Try to fetch the user's profile to get their profile picture
    let mut profile_data = None;
    let mut avatar_blob = None;
    let mut avatar_blob_cid = None;
    
    match fetch_user_profile(&state, &session.did, &token_set).await {
        Ok(data) => {
            profile_data = Some(data.clone());
            
            // Extract the avatar blob cid from the profile
            info!("Got profile data: {}", serde_json::to_string_pretty(&data).unwrap_or_default());
            
            if let Some(value) = data.get("value") {
                info!("Found profile value");
                if let Some(avatar) = value.get("avatar") {
                    info!("Found avatar field: {:?}", avatar);
                    if let Some(ref_val) = avatar.as_str() {
                        info!("Extracted avatar blob CID: {}", ref_val);
                        avatar_blob_cid = Some(ref_val.to_string());
                        
                        // Try to fetch the avatar blob
                        match fetch_blob(&state, &session.did, &token_set, ref_val).await {
                            Ok(blob_data) => {
                                info!("Successfully fetched avatar blob ({} bytes)", blob_data.len());
                                avatar_blob = Some(blob_data);
                            },
                            Err(e) => {
                                error!("Failed to fetch avatar blob: {:?}", e);
                            }
                        }
                    } else {
                        error!("Avatar field is not a string: {:?}", avatar);
                    }
                } else {
                    info!("No avatar field found in profile");
                }
            } else {
                error!("Missing 'value' field in profile data");
            }
        },
        Err(e) => {
            error!("Failed to fetch user profile: {:?}", e);
            // Don't fail the auth flow, just continue without profile data
        }
    }
    
    // Encode the image as base64 if we have one
    let avatar_base64 = avatar_blob.as_ref().map(|blob| {
        let content_type = "image/jpeg"; // Assuming JPEG format, but in production should detect from headers
        format!("data:{};base64,{}", content_type, base64::Engine::encode(&base64::engine::general_purpose::STANDARD, blob))
    });
    
    // Success page with profile information
    maud::html! {
        h1 { "Authentication Successful" }
        p { "You are now authenticated with Bluesky." }
        p { "DID: " (session.did) }
        p { "Access token expires in: " (token_set.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()) " seconds" }
        p { "Refresh token: " (token_set.refresh_token.is_some()) }
        
        div {
            h2 { "Profile Picture" }
            
            @if let Some(cid) = &avatar_blob_cid {
                p { "Blob CID: " (cid) }
                
                @if let Some(img_src) = &avatar_base64 {
                    p { "Image loaded successfully." }
                    img src=(img_src) alt="Profile Picture" style="max-width: 200px; max-height: 200px;" {}
                } @else {
                    p { 
                        strong { "Failed to load profile picture from CID" }
                    }
                }
            } @else {
                p { "No avatar CID found in profile data" }
            }
            
            @if avatar_blob.is_some() {
                p { "Blob data was successfully fetched" }
            }
        }
        
        @if let Some(data) = profile_data {
            div {
                h2 { "Profile Data (JSON)" }
                pre {
                    code {
                        (serde_json::to_string_pretty(&data).unwrap_or_else(|_| "Failed to format profile data".to_string()))
                    }
                }
            }
        }
        
        p { 
            a href="/" { "Return to Home" }
        }
    }.into_response()
}

/// Get a token for a DID
pub async fn get_token(
    State(state): State<AppState>,
    Query(params): Query<GetTokenParams>,
) -> impl IntoResponse {
    // Get the token for the given DID
    let token = match oauth::db::get_token(&state.db, &params.did).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                "No active token found for this DID".to_string(),
            ).into_response();
        }
        Err(err) => {
            error!("Failed to retrieve token: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve token".to_string(),
            ).into_response();
        }
    };
    
    // Check if the token is expired
    if token.is_expired() {
        // If we have a refresh token, try to refresh it
        if let Some(refresh_token) = &token.refresh_token {
            let client_id = state.client_id();
            
            // Try to get the session to get the stored DPoP nonce
            let session_id = uuid::Uuid::new_v4(); // Dummy UUID for this request
            let session = match oauth::db::get_session(&state.db, session_id).await {
                Ok(Some(s)) => s,
                _ => OAuthSession::new(params.did.clone(), None, params.token_endpoint.clone().unwrap_or_default()),
            };
            
            match oauth::refresh_token(
                &state.bsky_oauth,
                &params.token_endpoint.unwrap_or_default(),
                &client_id,
                refresh_token,
                session.dpop_nonce.as_deref(),
            ).await {
                Ok(token_response) => {
                    // Create a new token set with JWK thumbprint
                    let new_token = match OAuthTokenSet::from_token_response_with_jwk(
                        &token_response, 
                        token.did.clone(),
                        &state.bsky_oauth.public_key
                    ) {
                        Ok(token) => token,
                        Err(err) => {
                            error!("Failed to create token set with JWK: {:?}", err);
                            // Fallback to standard token creation
                            OAuthTokenSet::from_token_response(token_response, token.did.clone())
                        }
                    };
                    
                    // Store the new token
                    if let Err(err) = oauth::db::store_token(&state.db, &new_token).await {
                        error!("Failed to store refreshed token: {:?}", err);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to store refreshed token".to_string(),
                        ).into_response();
                    }
                    
                    // Return the refreshed token
                    return Json(serde_json::json!({
                        "did": new_token.did,
                        "access_token": new_token.access_token,
                        "token_type": new_token.token_type,
                        "expires_in": new_token.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        "scope": new_token.scope,
                        "status": "refreshed"
                    })).into_response();
                }
                Err(err) => {
                    error!("Failed to refresh token: {:?}", err);
                    
                    // Deactivate the expired token
                    if let Err(e) = oauth::db::deactivate_token(&state.db, &token.did).await {
                        error!("Failed to deactivate expired token: {:?}", e);
                    }
                    
                    return (
                        StatusCode::UNAUTHORIZED,
                        "Token expired and refresh failed. Please authenticate again.".to_string(),
                    ).into_response();
                }
            }
        } else {
            // No refresh token, need to authenticate again
            
            // Deactivate the expired token
            if let Err(e) = oauth::db::deactivate_token(&state.db, &token.did).await {
                error!("Failed to deactivate expired token: {:?}", e);
            }
            
            return (
                StatusCode::UNAUTHORIZED,
                "Token expired. Please authenticate again.".to_string(),
            ).into_response();
        }
    }
    
    // Token is valid, return it
    Json(serde_json::json!({
        "did": token.did,
        "access_token": token.access_token,
        "token_type": token.token_type,
        "expires_in": token.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        "scope": token.scope,
        "status": "valid"
    })).into_response()
}

/// Invalidate a token for a DID
pub async fn revoke_token(
    State(state): State<AppState>,
    Query(params): Query<RevokeTokenParams>,
) -> impl IntoResponse {
    // Deactivate the token
    match oauth::db::deactivate_token(&state.db, &params.did).await {
        Ok(_) => {
            Json(serde_json::json!({
                "status": "success",
                "message": "Token revoked successfully"
            })).into_response()
        }
        Err(err) => {
            error!("Failed to revoke token: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to revoke token".to_string(),
            ).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct GetTokenParams {
    pub did: String,
    pub token_endpoint: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeTokenParams {
    pub did: String,
}
