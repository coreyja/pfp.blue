use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use color_eyre::eyre::eyre;
use maud::html;
use serde::Deserialize;
use sqlx::Row;
use std::{str::FromStr, time::SystemTime};
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
    let redirect_uri = params.redirect_uri.unwrap_or_else(|| state.redirect_uri());

    // Log the input parameters for debugging
    info!(
        "Authorize called with did: {}, redirect_uri: {:?}, state: {:?}",
        params.did, redirect_uri, params.state
    );

    // Determine if input is a handle or DID
    let did_str = params.did.clone();
    let did = if did_str.starts_with("did:") {
        // Input is already a DID
        match atrium_api::types::string::Did::new(did_str.clone()) {
            Ok(did) => did,
            Err(_) => {
                error!("Invalid DID: {}", did_str);
                return (StatusCode::BAD_REQUEST, "Invalid DID".to_string()).into_response();
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
            }
            Err(_) => {
                error!("Invalid handle: {}", did_str);
                return (StatusCode::BAD_REQUEST, "Invalid handle".to_string()).into_response();
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

    let auth_metadata =
        match crate::did::document_to_auth_server_metadata(&did_doc, state.bsky_client.clone())
            .await
        {
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
    info!(
        "Session ID: {}, Code Challenge: {}",
        session_id, code_challenge
    );
    Redirect::to(&auth_url).into_response()
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

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
        "https://bsky.social/xrpc/com.atproto.repo.getRecord", // Use standard PDS URL
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

        return Err(eyre!(
            "Failed to fetch user profile: {} - {}",
            status,
            error_text
        ));
    }

    // Parse the response JSON
    let profile_data = response.json::<serde_json::Value>().await?;

    Ok(profile_data)
}

/// Fetch a blob by its CID directly from the user's PDS
async fn fetch_blob_by_cid(did_or_handle: &str, cid: &str) -> cja::Result<Vec<u8>> {
    info!(
        "Fetching blob with CID: {} for DID/handle: {}",
        cid, did_or_handle
    );

    // First, resolve the user's DID document to find their PDS endpoint
    let client = reqwest::Client::new();
    let xrpc_client = std::sync::Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
        "https://bsky.social",
    ));

    // Check if the input is a handle or a DID
    let did_obj = if did_or_handle.starts_with("did:") {
        // It's already a DID
        atrium_api::types::string::Did::from_str(did_or_handle)
            .map_err(|e| eyre!("Invalid DID format: {}", e))?
    } else {
        // It's a handle, try to resolve it to a DID first
        let handle = atrium_api::types::string::Handle::from_str(did_or_handle)
            .map_err(|e| eyre!("Invalid handle format: {}", e))?;

        info!("Resolving handle {} to DID", did_or_handle);
        crate::did::resolve_handle_to_did(&handle, xrpc_client.clone()).await?
    };

    info!("Resolving DID document for {}", did_obj.as_str());
    let did_document = crate::did::resolve_did_to_document(&did_obj, xrpc_client).await?;

    // Find the PDS service endpoint
    let services = did_document
        .service
        .as_ref()
        .ok_or_else(|| eyre!("No service endpoints found in DID document"))?;

    let pds_service = services
        .iter()
        .find(|s| s.id == "#atproto_pds")
        .ok_or_else(|| eyre!("No ATProto PDS service endpoint found in DID document"))?;

    let pds_endpoint = &pds_service.service_endpoint;
    info!("Found PDS endpoint: {}", pds_endpoint);

    // Construct the getBlob URL using the PDS endpoint with the resolved DID
    let blob_url = format!(
        "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
        pds_endpoint,
        did_obj.as_str(),
        cid
    );
    info!("Requesting blob from PDS: {}", blob_url);

    // Create a request for the blob
    let request = client.get(&blob_url);

    // Send the request
    let response = request.send().await?;

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
            "https://avatar.bsky.social/img/avatar/plain/{}/{}@jpeg",
            did_obj.as_str(),
            cid
        );

        match client.get(&cdn_url).send().await {
            Ok(cdn_response) => {
                if cdn_response.status().is_success() {
                    let blob_data = cdn_response.bytes().await?.to_vec();
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
        let blob_data = response.bytes().await?.to_vec();
        info!(
            "Successfully retrieved blob from PDS: {} bytes",
            blob_data.len()
        );
        Ok(blob_data)
    }
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
    info!(
        "Callback received: code: {:?}, state: {:?}, error: {:?}, error_description: {:?}",
        params.code, params.state, params.error, params.error_description
    );

    // Also log cookie info
    if let Some(session_cookie) = cookies.get("bsky_session_id") {
        info!("Found session cookie: {}", session_cookie.value());
    } else {
        info!("No session cookie found");
    }

    // If we have an error, display it
    if let Some(error) = params.error {
        let error_description = params
            .error_description
            .unwrap_or_else(|| "No error description provided".to_string());
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
        }
        .into_response();
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
            }
            .into_response();
        }
    };

    info!("Received code: {}, state: {:?}", code, params.state);

    // Get the session ID from the state parameter or the cookie
    let session_id = match params
        .state
        .as_ref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            cookies
                .get("bsky_session_id")
                .and_then(|c| Uuid::parse_str(c.value()).ok())
        }) {
        Some(id) => id,
        None => {
            error!("No valid session ID found in state or cookie");
            return (
                StatusCode::BAD_REQUEST,
                "No valid session found. Please try authenticating again.".to_string(),
            )
                .into_response();
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
            )
                .into_response();
        }
        Err(err) => {
            error!("Failed to retrieve session: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve session data".to_string(),
            )
                .into_response();
        }
    };

    // Check if the session is expired
    if session.is_expired() {
        error!("Session expired: {}", session_id);
        return (
            StatusCode::BAD_REQUEST,
            "Session expired. Please try authenticating again.".to_string(),
        )
            .into_response();
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
            session.dpop_nonce.as_deref(), // Use the stored nonce if available
        )
        .await
        {
            Ok(response) => {
                token_response = Some(response);
            }
            Err(err) => {
                last_error = Some(err.to_string());

                // Check if the error contains a DPoP nonce error
                if last_error.as_ref().unwrap().contains("use_dpop_nonce")
                    || last_error.as_ref().unwrap().contains("nonce mismatch")
                {
                    // Try to extract the nonce from the error message
                    if let Some(nonce_start) =
                        last_error.as_ref().unwrap().find("\"dpop_nonce\":\"")
                    {
                        let nonce_substring = &last_error.as_ref().unwrap()[nonce_start + 14..];
                        if let Some(nonce_end) = nonce_substring.find('\"') {
                            let new_nonce = &nonce_substring[..nonce_end];

                            // Save the new nonce in the database for this session
                            if let Err(e) =
                                oauth::db::update_session_nonce(&state.db, session_id, new_nonce)
                                    .await
                            {
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
            let error_msg = last_error
                .as_ref()
                .unwrap_or(&"Unknown error".to_string())
                .clone();
            error!("Token exchange failed: {:?}", error_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to exchange authorization code for token: {:?}",
                    error_msg
                ),
            )
                .into_response();
        }
    };

    // Check if there's an existing user session
    let current_user_id =
        if let Some(session_id) = crate::auth::get_session_id_from_cookie(&cookies) {
            match crate::auth::validate_session(&state.db, session_id).await {
                Ok(Some(user_session)) => {
                    // User is already logged in, get their ID
                    match user_session.get_user(&state.db).await {
                        Ok(Some(user)) => {
                            info!(
                                "Found existing user session, linking new account to user_id: {}",
                                user.user_id
                            );
                            Some(user.user_id)
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        } else {
            None
        };

    // Create a token set with JWK thumbprint and user_id if we have one
    let mut token_set = match OAuthTokenSet::from_token_response_with_jwk(
        &token_response,
        session.did.clone(),
        &state.bsky_oauth.public_key,
    ) {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to create token set with JWK: {:?}", err);
            // Fallback to standard token creation without JWK calculation
            OAuthTokenSet::from_token_response(token_response, session.did.clone())
        }
    };

    // If we found a user session, associate this token with that user
    if let Some(user_id) = current_user_id {
        token_set.user_id = Some(user_id);
    }

    // Store the token in the database
    if let Err(err) = oauth::db::store_token(&state.db, &token_set).await {
        error!("Failed to store token: {:?}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to store access token".to_string(),
        )
            .into_response();
    }

    info!("Authentication successful for DID: {}", session.did);

    // Profile image fetching and display is handled in display_profile_multi function

    // Check if we already have a user from the token set
    let user_id = if let Some(user_id) = token_set.user_id {
        // We already have a linked user from the existing session
        user_id
    } else {
        // We need to find or create a user for this token
        match crate::user::User::get_by_did(&state.db, &session.did).await {
            Ok(Some(user)) => user.user_id,
            Ok(None) => {
                // Create a new user
                match crate::user::User::create(&state.db, None, None).await {
                    Ok(user) => user.user_id,
                    Err(err) => {
                        error!("Failed to create user: {:?}", err);
                        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user")
                            .into_response();
                    }
                }
            }
            Err(err) => {
                error!("Failed to find user: {:?}", err);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    };

    // Check if we already have a session
    let have_session = if let Some(session_id) = crate::auth::get_session_id_from_cookie(&cookies) {
        matches!(
            crate::auth::validate_session(&state.db, session_id).await,
            Ok(Some(_))
        )
    } else {
        false
    };

    // Only create a new session if we don't already have one
    if !have_session {
        // Create a session for this user
        let user_agent_str = None; // Simplify by not using User-Agent header for now
        let ip_address = None; // Simplified to not use client IP address

        // Create a session
        if let Err(err) = crate::auth::create_session_and_set_cookie(
            &state.db,
            &cookies,
            user_id,
            user_agent_str,
            ip_address,
        )
        .await
        {
            error!("Failed to create session: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session",
            )
                .into_response();
        }
    }

    // For backward compatibility, also set the legacy DID cookie
    let mut legacy_cookie = Cookie::new(AUTH_DID_COOKIE, session.did.clone());
    legacy_cookie.set_path("/");
    legacy_cookie.set_max_age(time::Duration::days(30));
    legacy_cookie.set_http_only(true);
    legacy_cookie.set_secure(true);

    cookies.add(legacy_cookie);

    // Redirect to the profile page
    info!("Setting auth cookies and redirecting to /me");
    Redirect::to("/me").into_response()
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
            )
                .into_response();
        }
        Err(err) => {
            error!("Failed to retrieve token: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve token".to_string(),
            )
                .into_response();
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
                _ => OAuthSession::new(
                    params.did.clone(),
                    None,
                    params.token_endpoint.clone().unwrap_or_default(),
                ),
            };

            match oauth::refresh_token(
                &state.bsky_oauth,
                &params.token_endpoint.unwrap_or_default(),
                &client_id,
                refresh_token,
                session.dpop_nonce.as_deref(),
            )
            .await
            {
                Ok(token_response) => {
                    // Create a new token set with JWK thumbprint
                    let new_token = match OAuthTokenSet::from_token_response_with_jwk(
                        &token_response,
                        token.did.clone(),
                        &state.bsky_oauth.public_key,
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
                        )
                            .into_response();
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
                    )
                        .into_response();
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
            )
                .into_response();
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
        Ok(_) => Json(serde_json::json!({
            "status": "success",
            "message": "Token revoked successfully"
        }))
        .into_response(),
        Err(err) => {
            error!("Failed to revoke token: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to revoke token".to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct GetTokenParams {
    pub did: String,
    pub token_endpoint: Option<String>,
}

/// Cookie name for storing the user's DID
pub const AUTH_DID_COOKIE: &str = "pfp_auth_did";

#[derive(Deserialize)]
pub struct RevokeTokenParams {
    pub did: String,
}

/// Profile page that requires authentication
pub async fn profile(
    State(state): State<AppState>,
    crate::auth::AuthUser(user): crate::auth::AuthUser,
) -> impl IntoResponse {
    // Get all tokens for this user
    let tokens = match oauth::db::get_tokens_for_user(&state.db, user.user_id).await {
        Ok(tokens) => tokens,
        Err(err) => {
            error!("Failed to retrieve tokens for user: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve tokens".to_string(),
            )
                .into_response();
        }
    };

    if tokens.is_empty() {
        return maud::html! {
            h1 { "Your Profile" }
            p { "You don't have any Bluesky accounts linked yet." }
            form action="/oauth/bsky/authorize" method="get" {
                input type="text" name="did" placeholder="Enter Bluesky handle or DID" style="width: 250px;" {}
                button type="submit" { "Link a Bluesky Account" }
            }
        }.into_response();
    }

    // Use the first token as the primary one
    let primary_token = tokens[0].clone();

    // Check if the primary token is expired and try to refresh it
    if primary_token.is_expired() {
        if let Some(refresh_token) = &primary_token.refresh_token {
            let client_id = state.client_id();

            // Try to get the latest DPoP nonce
            let dpop_nonce = match oauth::db::get_latest_nonce(&state.db, &primary_token.did).await
            {
                Ok(nonce) => nonce,
                Err(err) => {
                    error!("Failed to get DPoP nonce: {:?}", err);
                    None
                }
            };

            // Lookup the token endpoint in the OAuthSession
            let token_endpoint =
                match get_token_endpoint_for_did(&state.db, &primary_token.did).await {
                    Ok(Some(endpoint)) => endpoint,
                    _ => {
                        // Fallback to bsky.social
                        "https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string()
                    }
                };

            match oauth::refresh_token(
                &state.bsky_oauth,
                &token_endpoint,
                &client_id,
                refresh_token,
                dpop_nonce.as_deref(),
            )
            .await
            {
                Ok(token_response) => {
                    // Create a new token set with JWK thumbprint
                    let new_token = match OAuthTokenSet::from_token_response_with_jwk(
                        &token_response,
                        primary_token.did.clone(),
                        &state.bsky_oauth.public_key,
                    ) {
                        Ok(token) => {
                            // Set the user_id
                            token.with_user_id(user.user_id)
                        }
                        Err(err) => {
                            error!("Failed to create token set with JWK: {:?}", err);
                            // Fallback to standard token creation
                            OAuthTokenSet::from_token_response(
                                token_response,
                                primary_token.did.clone(),
                            )
                            .with_user_id(user.user_id)
                        }
                    };

                    // Store the new token
                    if let Err(err) = oauth::db::store_token(&state.db, &new_token).await {
                        error!("Failed to store refreshed token: {:?}", err);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to store refreshed token".to_string(),
                        )
                            .into_response();
                    }

                    // Refresh all tokens
                    let tokens = match oauth::db::get_tokens_for_user(&state.db, user.user_id).await
                    {
                        Ok(tokens) => tokens,
                        Err(_) => vec![new_token.clone()],
                    };

                    // Display the profile with the refreshed token and all tokens
                    return display_profile_multi(&state, new_token, tokens)
                        .await
                        .into_response();
                }
                Err(err) => {
                    error!("Failed to refresh token: {:?}", err);
                    // Token refresh failed, but we still show the profile with expired token
                    // so the user can see other linked accounts
                }
            }
        }
    }

    // Display profile with all tokens
    display_profile_multi(&state, primary_token, tokens)
        .await
        .into_response()
}

/// Helper function to get the token endpoint for a DID from stored sessions
async fn get_token_endpoint_for_did(pool: &sqlx::PgPool, did: &str) -> cja::Result<Option<String>> {
    let row = sqlx::query(
        r#"
        SELECT token_endpoint FROM oauth_sessions 
        WHERE did = $1 
        ORDER BY updated_at_utc DESC 
        LIMIT 1
        "#,
    )
    .bind(did)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.get("token_endpoint")))
}

/// Display profile information with multiple linked accounts
async fn display_profile_multi(
    state: &AppState,
    primary_token: OAuthTokenSet,
    all_tokens: Vec<OAuthTokenSet>,
) -> maud::Markup {
    // Fetch primary profile data
    let profile_data = match fetch_user_profile(state, &primary_token.did, &primary_token).await {
        Ok(data) => Some(data),
        Err(e) => {
            error!("Failed to fetch user profile: {:?}", e);
            None
        }
    };

    // Try to extract avatar CID from profile
    let mut avatar_blob_cid = None;
    if let Some(data) = &profile_data {
        if let Some(value) = data.get("value") {
            if let Some(avatar) = value.get("avatar") {
                if let Some(ref_obj) = avatar.get("ref") {
                    if let Some(link) = ref_obj.get("$link") {
                        if let Some(cid_str) = link.as_str() {
                            avatar_blob_cid = Some(cid_str.to_string());
                            info!("Found avatar blob CID: {}", cid_str);
                        }
                    }
                }
            }
        }
    }

    // Try to fetch avatar blob
    let avatar_blob = if let Some(ref cid) = avatar_blob_cid {
        match fetch_blob_by_cid(&primary_token.did, cid).await {
            Ok(blob) => {
                info!("Successfully fetched avatar blob: {} bytes", blob.len());
                Some(blob)
            }
            Err(e) => {
                error!("Failed to fetch avatar blob: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    // Determine mime type for image
    let mut mime_type = "image/jpeg"; // Default if we can't detect

    // Try to extract the mime type from the profile data
    if let Some(data) = &profile_data {
        if let Some(value) = data.get("value") {
            if let Some(avatar) = value.get("avatar") {
                if let Some(mime) = avatar.get("mimeType") {
                    if let Some(mime_str) = mime.as_str() {
                        mime_type = mime_str;
                        info!("Detected mime type from profile: {}", mime_type);
                    }
                }
            }
        }
    }

    // Encode avatar as base64
    let avatar_base64 = avatar_blob.as_ref().map(|blob| {
        format!(
            "data:{};base64,{}",
            mime_type,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, blob)
        )
    });

    // Extract display name and handle from profile
    let mut display_name = primary_token.did.clone();
    let mut handle = None;

    if let Some(data) = &profile_data {
        if let Some(value) = data.get("value") {
            if let Some(name) = value.get("displayName") {
                if let Some(name_str) = name.as_str() {
                    display_name = name_str.to_string();
                }
            }

            if let Some(h) = value.get("handle") {
                if let Some(h_str) = h.as_str() {
                    handle = Some(h_str.to_string());
                }
            }
        }
    }

    // Create profile display
    html! {
        h1 { "Your Profile" }

        div class="profile-container" {
            div class="profile-header" {
                @if let Some(img_src) = &avatar_base64 {
                    img src=(img_src) alt="Profile Picture" style="max-width: 150px; max-height: 150px; border-radius: 50%;" {}
                } @else {
                    div style="width: 150px; height: 150px; background-color: #ccc; border-radius: 50%; display: flex; align-items: center; justify-content: center;" {
                        "No Image"
                    }
                }

                div class="profile-info" {
                    h2 { (display_name) }
                    @if let Some(h) = &handle {
                        p { "@" (h) }
                    }
                    p { "DID: " (primary_token.did) }
                }
            }

            div class="token-info" {
                h3 { "Authentication Info" }
                p { "Access token expires in: " (primary_token.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()) " seconds" }
                p { "Has refresh token: " (primary_token.refresh_token.is_some()) }
            }

            // Display all linked accounts
            div class="linked-accounts" {
                h3 { "Linked Bluesky Accounts" }

                ul {
                    @for token in &all_tokens {
                        li {
                            strong { "DID: " (token.did) }
                            @if token.did == primary_token.did {
                                span style="color: green;" { " (Current)" }
                            }
                            p { "Expires in: " (token.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()) " seconds" }
                        }
                    }
                }

                p {
                    form action="/oauth/bsky/authorize" method="get" {
                        input type="text" name="did" placeholder="Enter Bluesky handle or DID" style="width: 250px;" {}
                        button type="submit" { "Link Another Bluesky Account" }
                    }
                }
            }

            @if let Some(data) = &profile_data {
                div class="profile-data" {
                    h3 { "Profile Data" }
                    details {
                        summary { "View Raw JSON" }
                        pre {
                            code {
                                (serde_json::to_string_pretty(data).unwrap_or_else(|_| "Failed to format profile data".to_string()))
                            }
                        }
                    }
                }
            }

            p {
                a href="/" { "Return to Home" }
                " | "
                a href="/logout" { "Logout" }
                " | "
                a href="/login" { "Sign in as another user" }
            }
        }
    }
}
