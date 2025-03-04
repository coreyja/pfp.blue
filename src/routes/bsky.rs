use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
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
        Some(redirect_uri.clone()),
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
    let token_response = match oauth::exchange_code_for_token(
        &state.bsky_oauth,
        &session.token_endpoint,
        &client_id,
        &code,
        &redirect_uri,
        code_verifier,
    ).await {
        Ok(token) => token,
        Err(err) => {
            error!("Token exchange failed: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to exchange authorization code for token: {:?}", err),
            ).into_response();
        }
    };
    
    // Create a token set
    let token_set = OAuthTokenSet::from_token_response(token_response, session.did.clone());
    
    // Store the token in the database
    if let Err(err) = oauth::db::store_token(&state.db, &token_set).await {
        error!("Failed to store token: {:?}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to store access token".to_string(),
        ).into_response();
    }
    
    info!("Authentication successful for DID: {}", session.did);
    
    // Redirect to the original redirect URI if present, otherwise show success
    if let Some(original_redirect) = session.redirect_uri {
        // Append the DID as a query parameter
        let redirect_to = if original_redirect.contains('?') {
            format!("{}&did={}", original_redirect, session.did)
        } else {
            format!("{}?did={}", original_redirect, session.did)
        };
        
        // Add the original state parameter if present
        let redirect_to = if let Some(state) = session.state {
            format!("{}&state={}", redirect_to, state)
        } else {
            redirect_to
        };
        
        Redirect::to(&redirect_to).into_response()
    } else {
        // Default success page
        maud::html! {
            h1 { "Authentication Successful" }
            p { "You are now authenticated with Bluesky." }
            p { "DID: " (session.did) }
            p { "Access token expires in: " (token_set.expires_at - SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()) " seconds" }
            p { "Refresh token: " (token_set.refresh_token.is_some()) }
            p { 
                a href="/" { "Return to Home" }
            }
        }.into_response()
    }
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
            
            match oauth::refresh_token(
                &state.bsky_oauth,
                &params.token_endpoint.unwrap_or_default(),
                &client_id,
                refresh_token,
            ).await {
                Ok(token_response) => {
                    // Create a new token set
                    let new_token = OAuthTokenSet::from_token_response(token_response, token.did.clone());
                    
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
