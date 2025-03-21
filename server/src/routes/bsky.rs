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
    let redirect_uri = params.redirect_uri.unwrap_or_else(|| state.redirect_uri());

    // Log the input parameters for debugging
    info!(
        "Authorize called with did: {}, redirect_uri: {:?}, state: {:?}",
        params.did, redirect_uri, params.state
    );

    // Resolve DID or handle using our helper function
    let did = match crate::did::resolve_did_or_handle(&params.did, state.bsky_client.clone()).await
    {
        Ok(did) => did,
        Err(err) => {
            error!("Invalid DID or handle {}: {:?}", params.did, err);
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid DID or handle: {:?}", err),
            )
                .into_response();
        }
    };

    // Get the DID document
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

    // Get auth metadata for the DID
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

// Function removed since it's not used anywhere - we use api::get_profile_with_avatar instead

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
    let did_obj =
        crate::did::resolve_did_or_handle(did_or_handle, app_state.bsky_client.clone()).await?;
    let did_str = did_obj.to_string();

    // Try to fetch the blob using our api module
    let client = reqwest::Client::new();
    let pds_endpoint =
        crate::api::find_pds_endpoint(&did_str, app_state.bsky_client.clone()).await?;

    // Construct the getBlob URL using the PDS endpoint with the resolved DID
    let blob_url = format!(
        "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
        pds_endpoint, did_str, cid
    );
    info!("Requesting blob from PDS: {}", blob_url);

    // Create a request for the blob
    let response = client.get(&blob_url).send().await?;

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

/// Helper function to handle OAuth error responses
fn handle_oauth_error(
    error: &str,
    error_description: Option<String>,
    client_id: &str,
    redirect_uri: &str,
) -> axum::response::Response {
    let error_description = error_description.unwrap_or_else(|| "No error description provided".to_string());
    error!("OAuth error: {} - {}", error, error_description);

    use crate::components::ui::{
        badge::{Badge, BadgeColor},
        button::Button, 
        heading::Heading,
    };

    // Create a styled error page
    let markup = html! {
        // Add Tailwind CSS from CDN
        script src="https://unpkg.com/@tailwindcss/browser@4" {}

        // Main container with gradient background
        div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
            div class="max-w-lg mx-auto bg-white rounded-2xl shadow-xl overflow-hidden" {
                div class="px-8 py-6" {
                    (Heading::h1("Authentication Error"))
                    p class="text-red-600 font-medium mb-4" { "There was an error during authentication:" }
                    
                    div class="mb-4" {
                        p class="text-gray-700" { "Error: " }
                        (Badge::new(error, BadgeColor::Red).rounded(true))
                    }
                    
                    div class="mb-6" {
                        p class="text-gray-700" { "Description: " }
                        p class="text-gray-600 italic" { (error_description) }
                    }
                    
                    details class="mb-6 bg-gray-50 p-3 rounded-lg" {
                        summary class="cursor-pointer font-medium text-gray-700" { "Debug Information" }
                        div class="mt-2 space-y-1 text-sm" {
                            p { "Client ID: " (client_id) }
                            p { "Redirect URI: " (redirect_uri) }
                        }
                    }
                    
                    div class="flex justify-center mt-4" {
                        (Button::primary("Return to Home").href("/"))
                    }
                }
            }

            // Footer credit
            div class="mt-8 text-center text-gray-500 text-sm" {
                p { "© 2025 pfp.blue - Bluesky Profile Management" }
            }
        }
    };

    markup.into_response()
}

/// Helper function to handle missing code error
fn handle_missing_code_error(state_param: Option<&str>, client_id: &str, redirect_uri: &str) -> axum::response::Response {
    error!("No code parameter in callback");

    use crate::components::ui::{
        button::{Button, ButtonVariant, IconPosition},
        heading::Heading,
        icon::Icon,
    };

    // Create a styled error page
    let markup = html! {
        // Add Tailwind CSS from CDN
        script src="https://unpkg.com/@tailwindcss/browser@4" {}

        // Main container with gradient background
        div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
            div class="max-w-lg mx-auto bg-white rounded-2xl shadow-xl overflow-hidden" {
                div class="px-8 py-6" {
                    (Heading::h1("Authentication Error"))
                    p class="text-red-600 font-medium mb-2" { "There was an error during the authorization process." }
                    p class="text-gray-700 mb-6" { "The Bluesky server did not provide an authorization code in the callback." }
                    
                    details class="mb-6 bg-gray-50 p-3 rounded-lg" {
                        summary class="cursor-pointer font-medium text-gray-700" { "Debug Information" }
                        div class="mt-2 space-y-1 text-sm" {
                            p { "State parameter: " (state_param.unwrap_or("None")) }
                            p { "Client ID: " (client_id) }
                            p { "Redirect URI: " (redirect_uri) }
                        }
                    }
                    
                    div class="flex flex-col sm:flex-row justify-center gap-4 mt-6" {
                        (Button::primary("Try Again")
                            .href("/login")
                            .icon(Icon::login().into_string(), IconPosition::Left))
                        
                        (Button::new("Return to Home")
                            .variant(ButtonVariant::Secondary)
                            .href("/")
                            .icon(Icon::home().into_string(), IconPosition::Left))
                    }
                }
            }

            // Footer credit
            div class="mt-8 text-center text-gray-500 text-sm" {
                p { "© 2025 pfp.blue - Bluesky Profile Management" }
            }
        }
    };

    markup.into_response()
}

/// Helper function to get session ID from state or cookie
async fn get_session_id_and_data(
    state_param: Option<&str>, 
    cookies: &Cookies,
    db_pool: &sqlx::PgPool
) -> Result<(Uuid, OAuthSession), (StatusCode, String)> {
    // Get the session ID from the state parameter or the cookie
    let session_id = match state_param
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            cookies
                .get("bsky_session_id")
                .and_then(|c| Uuid::parse_str(c.value()).ok())
        }) {
        Some(id) => id,
        None => {
            error!("No valid session ID found in state or cookie");
            return Err((
                StatusCode::BAD_REQUEST,
                "No valid session found. Please try authenticating again.".to_string(),
            ));
        }
    };

    // Retrieve session data from the database
    let session = match oauth::db::get_session(db_pool, session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            error!("Session not found: {}", session_id);
            return Err((
                StatusCode::BAD_REQUEST,
                "Session not found. Please try authenticating again.".to_string(),
            ));
        }
        Err(err) => {
            error!("Failed to retrieve session: {:?}", err);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve session data".to_string(),
            ));
        }
    };

    // Check if the session is expired
    if session.is_expired() {
        error!("Session expired: {}", session_id);
        return Err((
            StatusCode::BAD_REQUEST,
            "Session expired. Please try authenticating again.".to_string(),
        ));
    }

    Ok((session_id, session))
}

/// Helper function to exchange code for token
async fn exchange_auth_code_for_token(
    oauth_config: &crate::state::BlueskyOAuthConfig,
    session_id: Uuid,
    session: &OAuthSession,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    db_pool: &sqlx::PgPool,
) -> Result<oauth::TokenResponse, (StatusCode, String)> {
    let code_verifier = session.code_verifier.as_deref();
    let mut attempts = 0;
    let mut last_error = None;
    let mut token_response = None;

    // Try up to 2 times - once with the stored nonce and once with a new nonce if needed
    while attempts < 2 && token_response.is_none() {
        match oauth::exchange_code_for_token(
            oauth_config,
            &session.token_endpoint,
            client_id,
            code,
            redirect_uri,
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
                    if let Some(nonce) = extract_dpop_nonce_from_error(last_error.as_ref().unwrap()) {
                        // Save the new nonce in the database for this session
                        if let Err(e) = oauth::db::update_session_nonce(db_pool, session_id, &nonce).await {
                            error!("Failed to update session nonce: {:?}", e);
                        } else {
                            // Continue to retry with the new nonce
                            attempts += 1;
                            continue;
                        }
                    }
                }

                // If we couldn't extract a nonce or it's not a nonce error, break
                break;
            }
        }

        attempts += 1;
    }

    match token_response {
        Some(token) => Ok(token),
        None => {
            let error_msg = last_error
                .unwrap_or_else(|| "Unknown error".to_string());
            error!("Token exchange failed: {:?}", error_msg);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to exchange authorization code for token: {:?}",
                    error_msg
                ),
            ))
        }
    }
}

/// Extract DPoP nonce from error message
fn extract_dpop_nonce_from_error(error_message: &str) -> Option<String> {
    if let Some(nonce_start) = error_message.find("\"dpop_nonce\":\"") {
        let nonce_substring = &error_message[nonce_start + 14..];
        if let Some(nonce_end) = nonce_substring.find('\"') {
            let new_nonce = &nonce_substring[..nonce_end];
            return Some(new_nonce.to_string());
        }
    }
    None
}

/// Helper function to get or create a user ID for a token
async fn get_or_create_user_id_for_token(
    token_set: &OAuthTokenSet,
    did: &str,
    db_pool: &sqlx::PgPool,
) -> Result<uuid::Uuid, (StatusCode, String)> {
    if let Some(user_id) = token_set.user_id {
        // We already have a linked user from the existing session
        return Ok(user_id);
    }
    
    // We need to find or create a user for this token
    match crate::user::User::get_by_did(db_pool, did).await {
        Ok(Some(user)) => Ok(user.user_id),
        Ok(None) => {
            // Create a new user
            match crate::user::User::create(db_pool, None, None).await {
                Ok(user) => Ok(user.user_id),
                Err(err) => {
                    error!("Failed to create user: {:?}", err);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user".to_string()))
                }
            }
        }
        Err(err) => {
            error!("Failed to find user: {:?}", err);
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))
        }
    }
}

/// Helper function to create a user session if needed
async fn ensure_user_session(
    cookies: &Cookies,
    db_pool: &sqlx::PgPool,
    user_id: uuid::Uuid,
    token_set: &OAuthTokenSet,
) -> Result<(), (StatusCode, String)> {
    // Check if we already have a session
    let have_session = if let Some(session_id) = crate::auth::get_session_id_from_cookie(cookies) {
        matches!(
            crate::auth::validate_session(db_pool, session_id).await,
            Ok(Some(_))
        )
    } else {
        false
    };

    // Only create a new session if we don't already have one
    if !have_session {
        // Get the token id to use as primary token
        let token_id = match sqlx::query!(
            r#"
            SELECT uuid_id FROM oauth_tokens WHERE did = $1
            "#,
            &token_set.did
        )
        .fetch_optional(db_pool)
        .await
        {
            Ok(Some(row)) => Some(row.uuid_id),
            _ => None,
        };

        if let Err(err) = crate::auth::create_session_and_set_cookie(
            db_pool,
            cookies,
            user_id,
            None, // User agent
            None, // IP address
            token_id, // Set this token as primary
        )
        .await
        {
            error!("Failed to create session: {:?}", err);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session".to_string(),
            ));
        }
    }

    Ok(())
}

/// Check if there's an existing user session and return user ID if found
async fn check_existing_user_session(
    cookies: &Cookies,
    db_pool: &sqlx::PgPool,
) -> Option<uuid::Uuid> {
    if let Some(session_id) = crate::auth::get_session_id_from_cookie(cookies) {
        match crate::auth::validate_session(db_pool, session_id).await {
            Ok(Some(user_session)) => {
                // User is already logged in, get their ID
                match user_session.get_user(db_pool).await {
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
    }
}

/// Handle the OAuth callback - main entry point
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
        return handle_oauth_error(&error, params.error_description, &client_id, &redirect_uri);
    }

    // Make sure we have a code
    let code = match params.code {
        Some(code) => code,
        None => {
            return handle_missing_code_error(params.state.as_deref(), &client_id, &redirect_uri);
        }
    };

    info!("Received code: {}, state: {:?}", code, params.state);

    // Get the session ID and data
    let (session_id, session) = match get_session_id_and_data(
        params.state.as_deref(),
        &cookies,
        &state.db
    ).await {
        Ok(result) => result,
        Err((status, message)) => {
            return (status, message).into_response();
        }
    };

    // Exchange the authorization code for an access token
    let token_response = match exchange_auth_code_for_token(
        &state.bsky_oauth,
        session_id,
        &session,
        &code,
        &client_id,
        &redirect_uri,
        &state.db
    ).await {
        Ok(token) => token,
        Err((status, message)) => {
            return (status, message).into_response();
        }
    };

    // Check if there's an existing user session
    let current_user_id = check_existing_user_session(&cookies, &state.db).await;

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

    // Schedule a background job to update the handle
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

    // Get or create a user ID for this token
    let user_id = match get_or_create_user_id_for_token(&token_set, &session.did, &state.db).await {
        Ok(id) => id,
        Err((status, message)) => {
            return (status, message).into_response();
        }
    };

    // Ensure we have a user session
    if let Err((status, message)) = ensure_user_session(&cookies, &state.db, user_id, &token_set).await {
        return (status, message).into_response();
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
        // Get token endpoint from parameters or fetch it
        let token_endpoint = match params.token_endpoint.clone() {
            Some(endpoint) => endpoint,
            None => {
                // Try to find a stored token endpoint or use default
                match get_token_endpoint_for_did(&state.db, &token.did).await {
                    Ok(Some(endpoint)) => endpoint,
                    _ => "https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string(),
                }
            }
        };

        // Attempt to refresh the token using our helper
        match oauth::refresh_token_if_needed(&token, &state, &token_endpoint).await {
            Ok(Some(new_token)) => {
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
            Ok(None) => {
                // This shouldn't happen - we already verified the token is expired
                error!("Token wasn't refreshed despite being expired");
            }
            Err(err) => {
                error!("Failed to refresh token: {:?}", err);

                // Delete the expired token
                if let Err(e) = oauth::db::delete_token(&state.db, &token.did).await {
                    error!("Failed to delete expired token: {:?}", e);
                }

                // No refresh token or refresh failed
                return (
                    StatusCode::UNAUTHORIZED,
                    "Token expired and refresh failed. Please authenticate again.".to_string(),
                )
                    .into_response();
            }
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
    let token = match sqlx::query!(
        r#"
        SELECT uuid_id FROM oauth_tokens
        WHERE did = $1 AND user_id = $2
        LIMIT 1
        "#,
        &params.did,
        user.user_id
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row.uuid_id,
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
        use crate::components::{
            form::{Form, InputField},
            profile::FeatureCard,
            ui::{
                button::{Button, ButtonVariant, IconPosition},
                heading::Heading,
                icon::Icon,
            },
        };

        let form_content = html! {
            (InputField::new("did")
                .placeholder("Enter Bluesky handle or DID")
                .icon(Icon::user())
                .required(true))
            
            (Button::primary("Link Bluesky Account")
                .icon(Icon::link().into_string(), IconPosition::Left)
                .button_type("submit")
                .full_width(true))
        };

        let markup = html! {
            // Add Tailwind CSS from CDN
            script src="https://unpkg.com/@tailwindcss/browser@4" {}

            // Empty state with playful design
            div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                div class="max-w-3xl mx-auto bg-white rounded-2xl shadow-xl overflow-hidden text-center p-8" {
                    // App logo
                    div class="mb-6 flex justify-center" {
                        (Icon::app_logo())
                    }

                    (Heading::h1("Welcome to Your Profile!")
                        .with_classes("text-center"))
                    p class="text-gray-600 mb-8 text-center" { 
                        "You don't have any Bluesky accounts linked yet. Let's get started!" 
                    }

                    // Auth form in a feature card style
                    div class="mb-8" {
                        (Form::new("/oauth/bsky/authorize", "get", form_content)
                            .extra_classes("bg-gradient-to-r from-indigo-50 to-blue-50 rounded-xl p-6 border border-dashed border-indigo-200"))
                    }

                    // Features section with cards
                    (Heading::h3("Why link your Bluesky account?"))
                    
                    div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8" {
                        (FeatureCard::new(
                            "Profile Management", 
                            "Manage your Bluesky profile with ease, including custom profile pictures",
                            "⚙️",
                            crate::components::profile::feature_card::FeatureCardColor::Blue
                        ))
                        
                        (FeatureCard::new(
                            "Multiple Accounts", 
                            "Link and manage multiple Bluesky accounts in one place",
                            "👥",
                            crate::components::profile::feature_card::FeatureCardColor::Indigo
                        ))
                        
                        (FeatureCard::new(
                            "Authentication", 
                            "Seamless authentication with your Bluesky identity",
                            "🔐",
                            crate::components::profile::feature_card::FeatureCardColor::Purple
                        ))
                    }

                    // Footer links
                    div class="mt-8 pt-4 border-t border-gray-200 flex justify-center gap-4" {
                        (Button::new("Back to Home")
                            .variant(ButtonVariant::Link)
                            .href("/")
                            .icon(Icon::home().into_string(), IconPosition::Left))
                            
                        span class="text-gray-300 self-center" { "|" }
                        
                        (Button::new("Try Different Login")
                            .variant(ButtonVariant::Link)
                            .href("/login")
                            .icon(Icon::login().into_string(), IconPosition::Left))
                    }
                }

                // Footer credit
                div class="mt-10 text-center text-gray-500 text-sm" {
                    p { "pfp.blue - Your Bluesky Profile Manager" }
                }
            }
        };

        return markup.into_response();
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
        // Lookup the token endpoint for refreshing
        let token_endpoint = match get_token_endpoint_for_did(&state.db, &primary_token.did).await {
            Ok(Some(endpoint)) => endpoint,
            _ => {
                // Resolve the PDS endpoint
                info!(
                    "No stored token endpoint found for DID: {}, resolving PDS",
                    &primary_token.did
                );
                match crate::api::find_pds_endpoint(&primary_token.did, state.bsky_client.clone())
                    .await
                {
                    Ok(pds_endpoint) => {
                        let refresh_endpoint =
                            format!("{}/xrpc/com.atproto.server.refreshSession", pds_endpoint);
                        info!("Resolved PDS endpoint for refresh: {}", refresh_endpoint);
                        refresh_endpoint
                    }
                    Err(e) => {
                        error!("Failed to resolve PDS endpoint: {:?}, using default", e);
                        "https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string()
                    }
                }
            }
        };

        // Use our helper function to attempt token refresh
        match oauth::refresh_token_if_needed(&primary_token, &state, &token_endpoint).await {
            Ok(Some(new_token)) => {
                // Refresh all tokens
                let tokens = match oauth::db::get_tokens_for_user(&state.db, user.user_id).await {
                    Ok(tokens) => tokens,
                    Err(_) => vec![new_token.clone()],
                };

                // Display the profile with the refreshed token and all tokens
                return display_profile_multi(&state, new_token, tokens)
                    .await
                    .into_response();
            }
            Ok(None) => {
                // Token wasn't refreshed (shouldn't happen as we already checked is_expired)
                info!("Token wasn't refreshed (unexpected - should be expired)");
            }
            Err(err) => {
                error!("Failed to refresh token: {:?}", err);
                // Token refresh failed, but we still show the profile with expired token
                // so the user can see other linked accounts
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
    let row = sqlx::query!(
        r#"
        SELECT token_endpoint FROM oauth_sessions
        WHERE did = $1
        ORDER BY updated_at_utc DESC
        LIMIT 1
        "#,
        did
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.token_endpoint))
}

/// Display profile information with multiple linked accounts
async fn display_profile_multi(
    state: &AppState,
    primary_token: OAuthTokenSet,
    all_tokens: Vec<OAuthTokenSet>,
) -> maud::Markup {
    use crate::components::{
        form::{Form, InputField, ToggleSwitch},
        profile::AccountCard,
        ui::{
            badge::{Badge, BadgeColor},
            button::{Button, ButtonSize, IconPosition},
            heading::Heading,
            icon::Icon,
            nav_buttons::{NavButton, NavButtonIcon, NavButtons},
        },
    };

    // Queue a job to update the handle in the background
    if let Err(err) = crate::jobs::UpdateProfileHandleJob::from_token(&primary_token)
        .enqueue(state.clone(), "display_profile_multi".to_string())
        .await
    {
        error!("Failed to enqueue handle update job for display: {:?}", err);
    }

    // Fetch profile data with avatar using our API helpers
    let profile_info = match crate::api::get_profile_with_avatar(&primary_token.did, state).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to fetch profile info: {:?}", e);
            // Create default profile info with just the DID
            crate::api::ProfileDataParams {
                display_name: None,
                handle: None,
                avatar: None,
                description: None,
                profile_data: None,
            }
        }
    };

    // Extract information for display
    let display_name = profile_info
        .display_name
        .unwrap_or_else(|| primary_token.did.clone());
    let handle = profile_info.handle;

    // Extract avatar information and encode as base64 if available
    let avatar_blob_cid = profile_info.avatar.as_ref().map(|a| a.cid.clone());

    // Encode avatar as base64 if available
    let avatar_base64 = if let Some(avatar) = &profile_info.avatar {
        avatar.data.as_ref().map(|data| format!(
                "data:{};base64,{}",
                avatar.mime_type,
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
            ))
    } else {
        None
    };

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
                            (Heading::h1(&display_name))
                            @if let Some(h) = &handle {
                                p class="text-lg text-indigo-600 font-semibold mb-2" { "@" (h) }
                            }
                            p class="text-sm text-gray-500 mb-4 max-w-md truncate" { (primary_token.did) }

                            // Playful badges
                            div class="flex flex-wrap justify-center md:justify-start gap-2 mt-2" {
                                (Badge::new("Profile", BadgeColor::Blue).rounded(true))
                                (Badge::new("Bluesky", BadgeColor::Green).rounded(true))
                                (Badge::new("pfp.blue", BadgeColor::Purple).rounded(true))
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

                    // Token info card using Heading and Badge components
                    div class="bg-indigo-50 rounded-xl p-4 mb-6" {
                        (Heading::h3("Authentication Status")
                            .with_color("text-indigo-800"))
                            
                        div class="grid grid-cols-1 md:grid-cols-2 gap-4" {
                            div class="bg-white rounded-lg p-3 shadow-sm" {
                                p class="text-sm text-gray-500" { "Token Expires In" }
                                p class="text-lg font-semibold" { 
                                    ({
                                        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                        if primary_token.expires_at > now {
                                            primary_token.expires_at - now
                                        } else {
                                            0
                                        }
                                    }) " seconds" 
                                }
                            }
                            div class="bg-white rounded-lg p-3 shadow-sm" {
                                p class="text-sm text-gray-500" { "Refresh Token" }
                                @if primary_token.refresh_token.is_some() {
                                    div class="flex items-center mt-1" {
                                        (Badge::new("Available", BadgeColor::Green).rounded(true))
                                    }
                                } @else {
                                    div class="flex items-center mt-1" {
                                        (Badge::new("Not Available", BadgeColor::Red).rounded(true))
                                    }
                                }
                            }
                        }
                    }

                    // Linked accounts section using AccountCard component
                    div class="mb-8" {
                        (Heading::h3("Linked Bluesky Accounts"))

                        div class="space-y-3" {
                            @for token in &all_tokens {
                                (AccountCard::new(&token.did, token.expires_at)
                                    .handle(token.handle.as_deref().unwrap_or(""))
                                    .is_primary(token.did == primary_token.did))
                            }
                        }

                        // Add new account form using Form, InputField and Button components
                        div class="mt-6 bg-gradient-to-r from-indigo-50 to-blue-50 rounded-xl p-5 border border-dashed border-indigo-200" {
                            (Form::new(
                                "/oauth/bsky/authorize", 
                                "get", 
                                html! {
                                    div class="flex flex-col sm:flex-row gap-2 items-center" {
                                        div class="w-full sm:flex-grow" {
                                            (InputField::new("did")
                                                .placeholder("Enter Bluesky handle or DID")
                                                .icon(Icon::user()))
                                        }
                                        
                                        (Button::primary("Link Account")
                                            .button_type("submit")
                                            .icon(Icon::plus().into_string(), IconPosition::Left))
                                    }
                                }
                            ).extra_classes("m-0"))
                        }
                    }

                    // Profile data section with improved styling
                    @if let Some(profile_data) = &profile_info.profile_data {
                        div class="mb-8" {
                            (Heading::h3("Profile Data"))
                            details class="bg-gray-50 rounded-lg border border-gray-200" {
                                summary class="cursor-pointer font-medium text-gray-700 p-4 hover:bg-gray-100" { "View Raw JSON" }
                                pre class="bg-gray-900 text-gray-100 p-4 rounded-b-lg overflow-x-auto text-sm" {
                                    code {
                                        (serde_json::to_string_pretty(profile_data).unwrap_or_else(|_| "Failed to format profile data".to_string()))
                                    }
                                }
                            }
                        }
                    }

                    // Profile Picture Progress feature
                    div class="mb-8" {
                        (Heading::h3("Profile Picture Progress"))
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

                            // Toggle switch for enabling/disabling using our ToggleSwitch component
                            form action="/profile_progress/toggle" method="post" class="mb-4" {
                                input type="hidden" name="token_id" value=(primary_token.did) {}
                                
                                (ToggleSwitch::new(
                                    "enabled", 
                                    "Enable Progress Visualization", 
                                    progress_settings.0
                                ).description("Automatically update your profile picture based on progress in your handle"))
                                
                                div class="mt-3 flex justify-end" {
                                    (Button::primary("Save")
                                        .button_type("submit")
                                        .size(ButtonSize::Small))
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
                                            (Button::primary("Use Current Profile Picture")
                                                .button_type("submit")
                                                .size(ButtonSize::Small))
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

                    // Action buttons footer using our new component
                    (NavButtons::new()
                        .add_button(NavButton::new("Home", "/")
                            .with_icon(NavButtonIcon::Home))
                        .add_button(NavButton::new("Logout", "/logout")
                            .with_icon(NavButtonIcon::Logout))
                        .add_button(NavButton::new("Switch User", "/login")
                            .with_icon(NavButtonIcon::Login)))
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