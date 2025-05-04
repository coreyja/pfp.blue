use atrium_oauth::{AuthorizeOptions, KnownScope, Scope};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use cja::server::cookies::CookieJar;
use sea_orm::{ActiveModelTrait as _, ActiveValue};
use serde::{Deserialize, Serialize};

use crate::{errors::ServerResult, state::AppState};

#[derive(Deserialize, Serialize)]
pub struct AuthParams {
    /// The user's Bluesky DID or Handle (will be resolved to DID if needed)
    pub did: String,
    /// Optional redirect URI for the OAuth flow
    pub redirect_uri: Option<String>,
    /// Optional state parameter to maintain state between requests
    pub state: Option<String>,
}

#[derive(Serialize)]
struct AuthUrlParams<'a> {
    client_id: &'a str,
    response_type: &'static str,
    scope: &'static str,
    redirect_uri: &'a str,
    state: &'a str,
    code_challenge: &'a str,
    code_challenge_method: &'static str,
}

/// Start the Bluesky OAuth flow
pub async fn authorize(
    State(state): State<AppState>,
    cookies: CookieJar<AppState>,
    Query(params): Query<AuthParams>,
) -> ServerResult<impl IntoResponse, StatusCode> {
    let client = state.atrium_oauth.clone();
    let url = client
        .authorize(
            params.did,
            AuthorizeOptions {
                scopes: vec![
                    Scope::Known(KnownScope::Atproto),
                    Scope::Known(KnownScope::TransitionGeneric),
                ],
                ..Default::default()
            },
        )
        .await?;
    Ok(Redirect::to(&url).into_response())
}

#[derive(Deserialize)]
pub struct SetPrimaryAccountParams {
    pub did: String,
    pub redirect: Option<String>,
}

/// Set a specific Bluesky account as the primary one
pub async fn set_primary_account(
    State(state): State<AppState>,
    cookies: CookieJar<AppState>,
    crate::auth::AuthUser { user, .. }: crate::auth::AuthUser,
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

    let mut session = match crate::auth::validate_session(&state, session_id).await {
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
        user.id
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

    let mut session: crate::orm::sessions::ActiveModel = session.into();
    session.primary_token_id = ActiveValue::set(Some(token));

    // Update the session with the new primary token
    if let Err(err) = session.update(&state.orm).await {
        tracing::error!("Failed to update primary token: {:?}", err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update primary account",
        )
            .into_response();
    }

    // Redirect back to provided path or profile page
    // FIX ME: Open redirect vulnerability here
    let redirect_path = params.redirect.unwrap_or_else(|| "/me".to_string());
    Redirect::to(&redirect_path).into_response()
}
