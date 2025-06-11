use atrium_oauth::{AuthorizeOptions, KnownScope, Scope};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::ServerResult, state::AppState};

use crate::prelude::*;

#[derive(Deserialize, Serialize)]
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
    Query(params): Query<AuthParams>,
) -> ServerResult<impl IntoResponse, StatusCode> {
    let client = state.atrium.oauth.clone();
    let url = client
        .authorize(
            params.did,
            AuthorizeOptions {
                redirect_uri: Some(state.redirect_uri()),
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
    pub account_id: Uuid,
    pub redirect: Option<String>,
}

/// Set a specific Bluesky account as the primary one
pub async fn set_primary_account(
    State(state): State<AppState>,
    crate::auth::AuthUser { user, session }: crate::auth::AuthUser,
    Query(params): Query<SetPrimaryAccountParams>,
) -> impl IntoResponse {
    let account = user
        .find_related(Accounts)
        .filter(crate::orm::accounts::Column::AccountId.eq(params.account_id))
        .one(&state.orm)
        .await
        .unwrap()
        .unwrap();

    let mut session: crate::orm::sessions::ActiveModel = session.into();
    session.primary_account_id = ActiveValue::set(account.account_id);

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
