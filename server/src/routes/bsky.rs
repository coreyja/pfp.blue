use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use cja::jobs::Job as _;
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

    // Create and store the OAuth session with the resolved DID
    let session = OAuthSession::new(
        did.to_string(), // Use the resolved DID, not the original input (which might be a handle)
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

/// Function to fetch profile data for display only (no authentication/DPoP needed)
async fn fetch_profile_for_display(did: &str) -> cja::Result<serde_json::Value> {
    use color_eyre::eyre::eyre;
    use tracing::info;

    let client = reqwest::Client::new();

    // First, resolve the DID document to find the PDS endpoint
    let xrpc_client = std::sync::Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
        "https://bsky.social",
    ));

    // Convert string DID to DID object
    let did_obj = match atrium_api::types::string::Did::new(did.to_string()) {
        Ok(did) => did,
        Err(err) => {
            return Err(eyre!("Invalid DID format: {}", err));
        }
    };

    // Resolve DID to document
    let did_document = match crate::did::resolve_did_to_document(&did_obj, xrpc_client).await {
        Ok(doc) => doc,
        Err(err) => {
            return Err(eyre!("Failed to resolve DID document: {}", err));
        }
    };

    // Find the PDS service endpoint
    let services = match did_document.service.as_ref() {
        Some(services) => services,
        None => {
            return Err(eyre!("No service endpoints found in DID document"));
        }
    };

    let pds_service = match services.iter().find(|s| s.id == "#atproto_pds") {
        Some(service) => service,
        None => {
            return Err(eyre!(
                "No ATProto PDS service endpoint found in DID document"
            ));
        }
    };

    let pds_endpoint = &pds_service.service_endpoint;
    info!("Found PDS endpoint for profile display: {}", pds_endpoint);

    // Construct the full URL to the PDS endpoint
    let get_record_url = format!("{}/xrpc/com.atproto.repo.getRecord", pds_endpoint);

    // Make unauthenticated API request to get profile directly from user's PDS
    let response = client
        .get(&get_record_url)
        .query(&[
            ("repo", did),
            ("collection", "app.bsky.actor.profile"),
            ("rkey", "self"),
        ])
        .send()
        .await?;

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
pub async fn fetch_blob_by_cid(did_or_handle: &str, cid: &str) -> cja::Result<Vec<u8>> {
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

    // Immediately fetch profile to get and update the handle
    // Use the job system to do this in the background
    if let Err(err) = crate::jobs::UpdateProfileHandleJob::from_token(&token_set)
        .enqueue(state.clone(), "callback".to_string())
        .await
    {
        // Log the error but continue - not fatal
        error!("Failed to enqueue handle update job: {:?}", err);
    } else {
        info!("Queued handle update job for DID: {}", session.did);
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
        // Get the token id to use as primary token
        let token_id = match sqlx::query(
            r#"
            SELECT uuid_id FROM oauth_tokens WHERE did = $1
            "#,
        )
        .bind(&token_set.did)
        .fetch_optional(&state.db)
        .await
        {
            Ok(Some(row)) => {
                let id: uuid::Uuid = row.get("uuid_id");
                Some(id)
            }
            _ => None,
        };

        if let Err(err) = crate::auth::create_session_and_set_cookie(
            &state.db,
            &cookies,
            user_id,
            user_agent_str,
            ip_address,
            token_id, // Set this token as primary
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

    // Also fetch profile in the background to ensure handle is up to date
    // Use the job system to do this asynchronously
    if let Err(err) = crate::jobs::UpdateProfileHandleJob::from_token(&token)
        .enqueue(state.clone(), "get_token".to_string())
        .await
    {
        error!(
            "Failed to enqueue handle update job in get_token: {:?}",
            err
        );
    } else {
        info!("Queued handle update job for DID: {}", token.did);
    }

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
                    // Create a new token set with JWK thumbprint and preserve the handle
                    let new_token = match OAuthTokenSet::from_token_response_with_jwk(
                        &token_response,
                        token.did.clone(),
                        &state.bsky_oauth.public_key,
                    ) {
                        Ok(new_token) => new_token.with_handle_from(&token),
                        Err(err) => {
                            error!("Failed to create token set with JWK: {:?}", err);
                            // Fallback to standard token creation
                            OAuthTokenSet::from_token_response(token_response, token.did.clone())
                                .with_handle_from(&token)
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

                    // Also fetch profile to update handle if needed (don't block on this)
                    // Use the job system to do this asynchronously
                    if let Err(err) = crate::jobs::UpdateProfileHandleJob::from_token(&new_token)
                        .enqueue(state.clone(), "get_token".to_string())
                        .await
                    {
                        error!(
                            "Failed to enqueue handle update job after token refresh: {:?}",
                            err
                        );
                    } else {
                        info!(
                            "Queued handle update job after token refresh for {}",
                            &new_token.did
                        );
                    }

                    // Return the refreshed token
                    return Json(serde_json::json!({
                        "did": new_token.did,
                        "access_token": new_token.access_token,
                        "token_type": new_token.token_type,
                        "expires_in": if new_token.expires_at > SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() {
                            new_token.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
                        } else { 0 },
                        "scope": new_token.scope,
                        "status": "refreshed"
                    })).into_response();
                }
                Err(err) => {
                    error!("Failed to refresh token: {:?}", err);

                    // Delete the expired token
                    if let Err(e) = oauth::db::delete_token(&state.db, &token.did).await {
                        error!("Failed to delete expired token: {:?}", e);
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

            // Delete the expired token
            if let Err(e) = oauth::db::delete_token(&state.db, &token.did).await {
                error!("Failed to delete expired token: {:?}", e);
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
        "expires_in": if token.expires_at > SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() {
            token.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
        } else { 0 },
        "scope": token.scope,
        "status": "valid"
    })).into_response()
}

/// Delete a token for a DID
pub async fn revoke_token(
    State(state): State<AppState>,
    Query(params): Query<RevokeTokenParams>,
) -> impl IntoResponse {
    // Delete the token
    match oauth::db::delete_token(&state.db, &params.did).await {
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

/// Set a specific Bluesky account as the primary one
pub async fn set_primary_account(
    State(state): State<AppState>,
    cookies: Cookies,
    crate::auth::AuthUser(user): crate::auth::AuthUser,
    Query(params): Query<SetPrimaryAccountParams>,
) -> impl IntoResponse {
    // Get the session
    let session_id = match crate::auth::get_session_id_from_cookie(&cookies) {
        Some(id) => id,
        None => {
            error!("No valid session found");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Session not found").into_response();
        }
    };

    let mut session = match crate::auth::validate_session(&state.db, session_id).await {
        Ok(Some(s)) => s,
        _ => {
            error!("Session validation failed");
            return Redirect::to("/login").into_response();
        }
    };

    // Verify that this DID belongs to this user
    let token = match sqlx::query(
        r#"
        SELECT uuid_id FROM oauth_tokens
        WHERE did = $1 AND user_id = $2
        LIMIT 1
        "#,
    )
    .bind(&params.did)
    .bind(user.user_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => {
            let id: uuid::Uuid = row.get("uuid_id");
            id
        }
        Ok(None) => {
            error!(
                "Attempted to set primary account for DID not belonging to user: {}",
                params.did
            );
            return (StatusCode::FORBIDDEN, "This account doesn't belong to you").into_response();
        }
        Err(err) => {
            error!("Database error when checking DID ownership: {:?}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    // Update the session with the new primary token
    if let Err(err) = session.set_primary_token(&state.db, token).await {
        error!("Failed to update primary token: {:?}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update primary account",
        )
            .into_response();
    }

    // Redirect back to profile page
    Redirect::to("/me").into_response()
}

#[derive(Deserialize)]
pub struct SetPrimaryAccountParams {
    pub did: String,
}

/// Profile page that requires authentication
pub async fn profile(
    State(state): State<AppState>,
    cookies: Cookies,
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

    // Start background jobs to update handles for all tokens
    // This ensures we have the latest handle data when displaying the profile
    for token in &tokens {
        if let Err(err) = crate::jobs::UpdateProfileHandleJob::from_token(token)
            .enqueue(state.clone(), "profile_route".to_string())
            .await
        {
            error!(
                "Failed to enqueue handle update job for DID {}: {:?}",
                token.did, err
            );
        }
    }

    if tokens.is_empty() {
        return maud::html! {
            // Add Tailwind CSS from CDN
            script src="https://unpkg.com/@tailwindcss/browser@4" {}

            // Empty state with playful design
            div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden text-center p-8" {
                    // Fun illustration
                    div class="mb-6 flex justify-center" {
                        (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" width="150" height="150" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" class="text-indigo-400"><circle cx="12" cy="8" r="5"></circle><path d="M20 21v-2a7 7 0 0 0-14 0v2"></path><line x1="12" y1="8" x2="12" y2="8"></line><path d="M3 20h18a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1H9L3 12v7a1 1 0 0 0 1 1z"></path></svg>"#))
                    }

                    h1 class="text-3xl font-bold text-gray-800 mb-4" { "Welcome to Your Profile!" }
                    p class="text-gray-600 mb-8" { "You don't have any Bluesky accounts linked yet. Let's get started!" }

                    // Playful form
                    div class="bg-gradient-to-r from-indigo-50 to-blue-50 rounded-xl p-6 border border-dashed border-indigo-200" {
                        form action="/oauth/bsky/authorize" method="get" class="space-y-4" {
                            // Fun section header
                            div class="flex items-center gap-2 mb-2" {
                                div class="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600" {
                                    "🚀"
                                }
                                h2 class="text-lg font-semibold text-indigo-800" { "Connect Your Bluesky" }
                            }

                            div class="relative" {
                                div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" {
                                    (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>"#))
                                }
                                input type="text" name="did" placeholder="Enter Bluesky handle or DID"
                                    class="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-gray-900" {}
                            }

                            button type="submit"
                                class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center" {
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>"#))
                                "Link Bluesky Account"
                            }
                        }
                    }

                    // Tips section
                    div class="mt-8 text-left" {
                        h3 class="text-lg font-semibold text-gray-800 mb-3" { "Why link your Bluesky account?" }
                        ul class="space-y-2 text-gray-600" {
                            li class="flex gap-2" {
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>"#))
                                span { "Manage your Bluesky profile with ease" }
                            }
                            li class="flex gap-2" {
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>"#))
                                span { "Multiple account support" }
                            }
                            li class="flex gap-2" {
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>"#))
                                span { "Seamless authentication" }
                            }
                        }
                    }

                    // Footer links
                    div class="mt-8 pt-4 border-t border-gray-200" {
                        div class="flex justify-center gap-4" {
                            a href="/" class="text-indigo-600 hover:text-indigo-800 transition-colors duration-200" { "Back to Home" }
                            span class="text-gray-300" { "|" }
                            a href="/login" class="text-indigo-600 hover:text-indigo-800 transition-colors duration-200" { "Try Different Login" }
                        }
                    }
                }

                // Footer credit
                div class="mt-10 text-center text-gray-500 text-sm" {
                    p { "pfp.blue - Your Bluesky Profile Manager" }
                }
            }
        }.into_response();
    }

    // Get session to check for a set primary token
    let session_id = match crate::auth::get_session_id_from_cookie(&cookies) {
        Some(id) => id,
        None => {
            error!("No valid session found");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Session not found").into_response();
        }
    };

    let session = match crate::auth::validate_session(&state.db, session_id).await {
        Ok(Some(s)) => s,
        _ => {
            error!("Session validation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid session").into_response();
        }
    };

    // Use primary token from session if available, otherwise use the first token
    let primary_token = if let Ok(Some(token)) = session.get_primary_token(&state.db).await {
        token
    } else if !tokens.is_empty() {
        tokens[0].clone()
    } else {
        error!("No tokens available for this user");
        return (StatusCode::BAD_REQUEST, "No Bluesky accounts linked").into_response();
    };

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
            let token_endpoint = match get_token_endpoint_for_did(&state.db, &primary_token.did)
                .await
            {
                Ok(Some(endpoint)) => endpoint,
                _ => {
                    // We need to resolve the PDS to get the correct endpoint
                    info!(
                        "No stored token endpoint found for DID: {}, resolving PDS",
                        &primary_token.did
                    );

                    // Try to resolve the PDS endpoint
                    let xrpc_client = std::sync::Arc::new(
                        atrium_xrpc_client::reqwest::ReqwestClient::new("https://bsky.social"),
                    );

                    match atrium_api::types::string::Did::new(primary_token.did.clone()) {
                        Ok(did_obj) => {
                            match crate::did::resolve_did_to_document(&did_obj, xrpc_client).await {
                                Ok(did_document) => {
                                    if let Some(services) = did_document.service.as_ref() {
                                        if let Some(pds_service) =
                                            services.iter().find(|s| s.id == "#atproto_pds")
                                        {
                                            let pds_endpoint = &pds_service.service_endpoint;
                                            let refresh_endpoint = format!(
                                                "{}/xrpc/com.atproto.server.refreshSession",
                                                pds_endpoint
                                            );
                                            info!(
                                                "Resolved PDS endpoint for refresh: {}",
                                                refresh_endpoint
                                            );
                                            refresh_endpoint
                                        } else {
                                            // Fallback to bsky.social if no PDS service found
                                            "https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string()
                                        }
                                    } else {
                                        // Fallback to bsky.social if no services found
                                        "https://bsky.social/xrpc/com.atproto.server.refreshSession"
                                            .to_string()
                                    }
                                }
                                Err(_) => {
                                    // Fallback to bsky.social on resolution error
                                    "https://bsky.social/xrpc/com.atproto.server.refreshSession"
                                        .to_string()
                                }
                            }
                        }
                        Err(_) => {
                            // Fallback to bsky.social on DID parse error
                            "https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string()
                        }
                    }
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
                    // Create a new token set with JWK thumbprint and preserve the handle
                    let new_token = match OAuthTokenSet::from_token_response_with_jwk(
                        &token_response,
                        primary_token.did.clone(),
                        &state.bsky_oauth.public_key,
                    ) {
                        Ok(token) => {
                            // Set the user_id and preserve the handle
                            token
                                .with_user_id(user.user_id)
                                .with_handle_from(&primary_token)
                        }
                        Err(err) => {
                            error!("Failed to create token set with JWK: {:?}", err);
                            // Fallback to standard token creation
                            OAuthTokenSet::from_token_response(
                                token_response,
                                primary_token.did.clone(),
                            )
                            .with_user_id(user.user_id)
                            .with_handle_from(&primary_token)
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

                    // Also fetch profile to update handle if needed (don't block on this)
                    // Use the job system to do this asynchronously
                    if let Err(err) = crate::jobs::UpdateProfileHandleJob::from_token(&new_token)
                        .enqueue(state.clone(), "profile_route".to_string())
                        .await
                    {
                        error!(
                            "Failed to enqueue handle update job after token refresh: {:?}",
                            err
                        );
                    } else {
                        info!(
                            "Queued handle update job after token refresh for {}",
                            &new_token.did
                        );
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
pub async fn get_token_endpoint_for_did(
    pool: &sqlx::PgPool,
    did: &str,
) -> cja::Result<Option<String>> {
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
    // Queue a job to update the handle in the background
    if let Err(err) = crate::jobs::UpdateProfileHandleJob::from_token(&primary_token)
        .enqueue(state.clone(), "display_profile_multi".to_string())
        .await
    {
        error!("Failed to enqueue handle update job for display: {:?}", err);
    }

    // Fetch profile data directly (we don't have to make this async since we're also updating in background)
    let profile_data = match fetch_profile_for_display(&primary_token.did).await {
        Ok(data) => Some(data),
        Err(e) => {
            error!("Failed to fetch user profile for display: {:?}", e);
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
        // Add Tailwind CSS from CDN
        script src="https://unpkg.com/@tailwindcss/browser@4" {}

        // Main container with a fun background gradient
        div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
            div class="max-w-3xl mx-auto bg-white rounded-2xl shadow-xl overflow-hidden" {
                // Profile header with fun curves
                div class="relative h-48 bg-gradient-to-r from-blue-500 to-indigo-600" {
                    div class="absolute left-0 right-0 bottom-0" {
                        (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 100" class="w-full h-20 fill-white"><path d="M0,64L80,69.3C160,75,320,85,480,80C640,75,800,53,960,42.7C1120,32,1280,32,1360,32L1440,32L1440,100L1360,100C1280,100,1120,100,960,100C800,100,640,100,480,100C320,100,160,100,80,100L0,100Z"></path></svg>"#))
                    }
                }

                // Profile content
                div class="px-6 py-8 -mt-20 relative z-10" {
                    // Avatar and name section
                    div class="flex flex-col md:flex-row items-center mb-8" {
                        // Avatar with playful border
                        div class="relative mb-4 md:mb-0 md:mr-6" {
                            @if let Some(img_src) = &avatar_base64 {
                                div class="rounded-full w-36 h-36 border-4 border-white shadow-lg overflow-hidden bg-white" {
                                    img src=(img_src) alt="Profile Picture" class="w-full h-full object-cover" {}
                                }
                            } @else {
                                div class="rounded-full w-36 h-36 border-4 border-white shadow-lg overflow-hidden bg-gradient-to-br from-blue-300 to-indigo-300 flex items-center justify-center text-white font-bold" {
                                    "No Image"
                                }
                            }
                            // Fun decorative element
                            div class="absolute -bottom-2 -right-2 w-10 h-10 rounded-full bg-yellow-400 shadow-md border-2 border-white flex items-center justify-center text-white text-xl" {
                                "👋"
                            }
                        }

                        // Profile info
                        div class="text-center md:text-left" {
                            h1 class="text-3xl font-bold text-gray-800 mb-1" { (display_name) }
                            @if let Some(h) = &handle {
                                p class="text-lg text-indigo-600 font-semibold mb-2" { "@" (h) }
                            }
                            p class="text-sm text-gray-500 mb-4 max-w-md truncate" { (primary_token.did) }

                            // Playful badges
                            div class="flex flex-wrap justify-center md:justify-start gap-2 mt-2" {
                                div class="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full" { "Profile" }
                                div class="bg-green-100 text-green-800 text-xs px-2 py-1 rounded-full" { "Bluesky" }
                                div class="bg-purple-100 text-purple-800 text-xs px-2 py-1 rounded-full" { "pfp.blue" }
                            }
                        }
                    }

                    // Tabs for different sections
                    div class="border-b border-gray-200 mb-6" {
                        div class="flex overflow-x-auto" {
                            button class="px-4 py-2 text-indigo-600 border-b-2 border-indigo-600 font-medium" { "Accounts" }
                            button class="px-4 py-2 text-gray-500 hover:text-indigo-600" { "Activity" }
                            button class="px-4 py-2 text-gray-500 hover:text-indigo-600" { "Settings" }
                        }
                    }

                    // Token info card
                    div class="bg-indigo-50 rounded-xl p-4 mb-6" {
                        h3 class="text-lg font-semibold text-indigo-800 mb-2" { "Authentication Status" }
                        div class="grid grid-cols-1 md:grid-cols-2 gap-4" {
                            div class="bg-white rounded-lg p-3 shadow-sm" {
                                p class="text-sm text-gray-500" { "Token Expires In" }
                                p class="text-lg font-semibold" { ({
                                    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                    if primary_token.expires_at > now {
                                        primary_token.expires_at - now
                                    } else {
                                        0
                                    }
                                }) " seconds" }
                            }
                            div class="bg-white rounded-lg p-3 shadow-sm" {
                                p class="text-sm text-gray-500" { "Refresh Token" }
                                @if primary_token.refresh_token.is_some() {
                                    p class="text-lg font-semibold text-green-600" { "Available ✓" }
                                } @else {
                                    p class="text-lg font-semibold text-red-600" { "Not Available ✗" }
                                }
                            }
                        }
                    }

                    // Linked accounts section
                    div class="mb-8" {
                        h3 class="text-xl font-bold text-gray-800 mb-4" { "Linked Bluesky Accounts" }

                        div class="space-y-3" {
                            @for token in &all_tokens {
                                div class="bg-white rounded-lg border border-gray-200 p-4 hover:shadow-md transition duration-200 relative overflow-hidden" {
                                    // Fun decorative element for primary account
                                    @if token.did == primary_token.did {
                                        div class="absolute top-0 right-0" {
                                            div class="bg-green-500 text-white text-xs transform rotate-45 px-8 py-1 translate-x-6 -translate-y-1 shadow-sm" {
                                                "PRIMARY"
                                            }
                                        }
                                    }

                                    div class="flex flex-col sm:flex-row sm:items-center justify-between" {
                                        div class="mb-2 sm:mb-0" {
                                            @if let Some(handle) = &token.handle {
                                                p class="font-medium text-gray-900 mb-1 truncate max-w-xs" { "@" (handle) }
                                                p class="text-xs text-gray-500 mb-1 truncate max-w-xs" { (token.did) }
                                            } @else {
                                                p class="font-medium text-gray-900 mb-1 truncate max-w-xs" { (token.did) }
                                            }
                                            p class="text-sm text-gray-500" { "Expires in: " ({
                                                let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                                if token.expires_at > now {
                                                    token.expires_at - now
                                                } else {
                                                    0
                                                }
                                            }) " seconds" }
                                        }

                                        @if token.did != primary_token.did {
                                            a href={"/oauth/bsky/set-primary?did=" (token.did)}
                                              class="text-sm bg-indigo-100 hover:bg-indigo-200 text-indigo-800 px-3 py-1 rounded-full inline-flex items-center transition-colors duration-200" {
                                                "Set as Primary"
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Add new account form with playful design
                        div class="mt-6 bg-gradient-to-r from-indigo-50 to-blue-50 rounded-xl p-5 border border-dashed border-indigo-200" {
                            form action="/oauth/bsky/authorize" method="get" class="flex flex-col sm:flex-row gap-2 items-center" {
                                div class="relative flex-grow" {
                                    div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" {
                                        (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>"#))
                                    }
                                    input type="text" name="did" placeholder="Enter Bluesky handle or DID"
                                        class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-gray-900" {}
                                }
                                button type="submit"
                                    class="w-full sm:w-auto bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center" {
                                    (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" /></svg>"#))
                                    "Link Account"
                                }
                            }
                        }
                    }

                    // Profile data section with improved styling
                    @if let Some(data) = &profile_data {
                        div class="mb-8" {
                            h3 class="text-xl font-bold text-gray-800 mb-4" { "Profile Data" }
                            details class="bg-gray-50 rounded-lg border border-gray-200" {
                                summary class="cursor-pointer font-medium text-gray-700 p-4 hover:bg-gray-100" { "View Raw JSON" }
                                pre class="bg-gray-900 text-gray-100 p-4 rounded-b-lg overflow-x-auto text-sm" {
                                    code {
                                        (serde_json::to_string_pretty(data).unwrap_or_else(|_| "Failed to format profile data".to_string()))
                                    }
                                }
                            }
                        }
                    }

                    // Profile Picture Progress feature
                    div class="mb-8" {
                        h3 class="text-xl font-bold text-gray-800 mb-4" { "Profile Picture Progress" }
                        div class="bg-indigo-50 rounded-xl p-5 border border-indigo-200" {
                            p class="text-gray-700 mb-4" {
                                "This feature automatically updates your profile picture to show progress from your handle. "
                                "Use a fraction (e.g. 3/10) or percentage (e.g. 30%) in your handle, and we'll visualize it!"
                            }

                            // Get profile progress settings for this token
                            @let progress_settings = match sqlx::query(
                                r#"
                                SELECT p.* FROM profile_picture_progress p
                                JOIN oauth_tokens t ON p.token_id = t.id
                                WHERE t.did = $1
                                "#
                            ).bind(&primary_token.did)
                              .fetch_optional(&state.db)
                              .await {
                                Ok(Some(row)) => {
                                    let enabled: bool = row.get("enabled");
                                    let original_blob_cid: Option<String> = row.get("original_blob_cid");
                                    (enabled, original_blob_cid)
                                },
                                _ => (false, None),
                            };

                            // Toggle switch for enabling/disabling
                            form action="/profile_progress/toggle" method="post" class="flex items-center justify-between mb-4 p-3 bg-white rounded-lg shadow-sm" {
                                div {
                                    p class="font-medium text-gray-900" { "Enable Progress Visualization" }
                                    p class="text-sm text-gray-500" { "Automatically update your profile picture based on progress in your handle" }
                                }

                                input type="hidden" name="token_id" value=(primary_token.did) {}

                                label class="relative inline-flex items-center cursor-pointer" {
                                    @if progress_settings.0 {
                                        input type="checkbox" name="enabled" value="true" checked class="sr-only peer" {}
                                    } @else {
                                        input type="checkbox" name="enabled" value="true" class="sr-only peer" {}
                                    }
                                    span class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600" {}
                                }

                                button type="submit" class="ml-2 bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1 rounded text-sm" {
                                    "Save"
                                }
                            }

                            // Original profile picture selection
                            form action="/profile_progress/set_original" method="post" class="p-3 bg-white rounded-lg shadow-sm" {
                                p class="font-medium text-gray-900 mb-2" { "Original Profile Picture" }
                                p class="text-sm text-gray-500 mb-4" { "Select the profile picture to use as the base for progress visualization" }

                                input type="hidden" name="token_id" value=(primary_token.did) {}

                                @if let Some(original_cid) = &progress_settings.1 {
                                    div class="mb-4 flex items-center" {
                                        p class="text-sm text-gray-600 mr-2" { "Current original: " }
                                        code class="bg-gray-100 px-2 py-1 rounded text-sm" { (original_cid) }
                                    }
                                }

                                @if let Some(img_src) = &avatar_base64 {
                                    div class="flex items-center space-x-4" {
                                        // Display current profile picture
                                        div class="w-16 h-16 rounded-full overflow-hidden bg-white" {
                                            img src=(img_src) alt="Current Profile Picture" class="w-full h-full object-cover" {}
                                        }

                                        // Use current button
                                        @if let Some(cid) = avatar_blob_cid.clone() {
                                            input type="hidden" name="blob_cid" value=(cid) {}
                                            button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1 rounded" {
                                                "Use Current Profile Picture"
                                            }
                                        }
                                    }
                                }
                            }

                            // Show how to format handle
                            div class="mt-4 p-3 bg-white rounded-lg shadow-sm" {
                                p class="font-medium text-gray-900 mb-2" { "How to format your handle" }
                                div class="space-y-2 text-sm text-gray-600" {
                                    p { "Your current handle: " @if let Some(h) = &handle {
                                        strong { "@" (h) }
                                    } @else { "None" }}
                                    p { "To show progress, format your handle with one of these patterns:" }
                                    ul class="list-disc list-inside ml-2 space-y-1" {
                                        li { "Fraction: " code class="bg-gray-100 px-1" { "username.3/10" } " — Shows 30% progress" }
                                        li { "Percentage: " code class="bg-gray-100 px-1" { "username.30%" } " — Shows 30% progress" }
                                        li { "Decimal: " code class="bg-gray-100 px-1" { "username.30.5%" } " — Shows 30.5% progress" }
                                    }
                                }
                            }
                        }
                    }

                    // Action buttons footer
                    div class="flex flex-wrap justify-center gap-3 pt-4 border-t border-gray-200" {
                        a href="/" class="flex items-center text-gray-700 hover:text-indigo-600 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors duration-200" {
                            (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7m-7-7v14" /></svg>"#))
                            "Home"
                        }
                        a href="/logout" class="flex items-center text-gray-700 hover:text-indigo-600 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors duration-200" {
                            (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>"#))
                            "Logout"
                        }
                        a href="/login" class="flex items-center text-gray-700 hover:text-indigo-600 px-3 py-2 rounded-lg hover:bg-gray-100 transition-colors duration-200" {
                            (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" /></svg>"#))
                            "Switch User"
                        }
                    }
                }
            }

            // Footer with credits
            div class="mt-10 text-center text-gray-500 text-sm" {
                p { "Designed with 💙 using TailwindCSS" }
                p class="mt-1" { "pfp.blue - Your Bluesky Profile Manager" }
            }
        }
    }
}
