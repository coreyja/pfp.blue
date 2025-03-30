use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use color_eyre::eyre::WrapErr;
use serde::Deserialize;
use tower_cookies::{Cookie, Cookies};
use tracing::info;

use crate::{
    errors::{ServerResult, WithStatus},
    oauth::{self, OAuthSession},
    state::AppState,
};

#[derive(Deserialize)]
pub struct AuthParams {
    /// The user's Bluesky DID or Handle (will be resolved to DID if needed)
    pub did: String,
    /// Optional redirect URI for the OAuth flow
    pub redirect_uri: Option<String>,
    /// Optional state parameter to maintain state between requests
    pub state: Option<String>,
}

/// Start the Bluesky OAuth flow
pub async fn authorize(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(params): Query<AuthParams>,
) -> ServerResult<impl IntoResponse, StatusCode> {
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
    let did = crate::did::resolve_did_or_handle(&params.did, state.bsky_client.clone())
        .await
        .wrap_err_with(|| format!("Invalid DID or handle: {}", params.did))
        .with_status(StatusCode::BAD_REQUEST)?;

    // Get the DID document
    let did_doc = crate::did::resolve_did_to_document(&did, state.bsky_client.clone())
        .await
        .wrap_err_with(|| format!("Failed to resolve DID document for: {:?}", did))
        .with_status(StatusCode::BAD_REQUEST)?;

    // Get auth metadata for the DID
    let auth_metadata =
        crate::did::document_to_auth_server_metadata(&did_doc, state.bsky_client.clone())
            .await
            .wrap_err("Failed to get auth server metadata")
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create and store the OAuth session with the resolved DID
    let session = OAuthSession::new(
        did.to_string(), // Use the resolved DID, not the original input (which might be a handle)
        params.state.clone(),
        auth_metadata.token_endpoint.clone(),
    );

    // Store the session in the database
    let session_id = oauth::db::store_session(&state, &session)
        .await
        .wrap_err("Failed to store OAuth session")
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

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
    Ok(Redirect::to(&auth_url).into_response())
}

#[derive(Deserialize)]
pub struct SetPrimaryAccountParams {
    pub did: String,
    pub redirect: Option<String>,
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
            tracing::error!("No valid session found");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Session not found").into_response();
        }
    };

    let mut session = match crate::auth::validate_session(&state.db, session_id).await {
        Ok(Some(s)) => s,
        _ => {
            tracing::error!("Session validation failed");
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
            tracing::error!(
                "Attempted to set primary account for DID not belonging to user: {}",
                params.did
            );
            return (StatusCode::FORBIDDEN, "This account doesn't belong to you").into_response();
        }
        Err(err) => {
            tracing::error!("Database error when checking DID ownership: {:?}", err);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    // Update the session with the new primary token
    if let Err(err) = session.set_primary_token(&state.db, token).await {
        tracing::error!("Failed to update primary token: {:?}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update primary account",
        )
            .into_response();
    }

    // Redirect back to provided path or profile page
    let redirect_path = params.redirect.unwrap_or_else(|| "/me".to_string());
    Redirect::to(&redirect_path).into_response()
}
