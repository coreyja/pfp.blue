use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use cja::jobs::Job;
use serde::Deserialize;
use std::time::SystemTime;
use tracing::{error, info};

use crate::{oauth, state::AppState};

#[derive(Deserialize)]
pub struct GetTokenParams {
    /// The DID to get a token for
    pub did: String,
    /// Optional token endpoint override (used by calling code but marked as unused by linter)
    
    pub token_endpoint: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeTokenParams {
    pub did: String,
}

/// Get a token for a DID
pub async fn get_token(
    State(state): State<AppState>,
    Query(params): Query<GetTokenParams>,
) -> impl IntoResponse {
    // Use our consolidated function to get a valid token
    match oauth::get_valid_token_by_did(&params.did, &state).await {
        Ok(token) => {
            // Also fetch profile in the background to ensure display name is up to date
            if let Err(err) = crate::jobs::UpdateProfileInfoJob::from_token(&token)
                .enqueue(state.clone(), "get_token".to_string())
                .await
            {
                error!(
                    "Failed to enqueue display name update job in get_token: {:?}",
                    err
                );
            } else {
                info!("Queued display name update job for DID: {}", token.did);
            }

            // Calculate the expires_in value
            let expires_in = if token.expires_at
                > SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            {
                token.expires_at
                    - SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
            } else {
                0
            };

            // Return the token data
            Json(serde_json::json!({
                "did": token.did,
                "access_token": token.access_token,
                "token_type": token.token_type,
                "expires_in": expires_in,
                "scope": token.scope,
                "status": if token.is_expired() { "expired" } else { "valid" }
            }))
            .into_response()
        }
        Err(err) => {
            error!("Error getting token: {:?}", err);

            if err.to_string().contains("No token found") {
                return (
                    StatusCode::NOT_FOUND,
                    "No active token found for this DID".to_string(),
                )
                    .into_response();
            }

            // Try to delete the token if it's failing to refresh
            if err.to_string().contains("Failed to refresh token") {
                if let Err(e) = oauth::db::delete_token(&state.db, &params.did).await {
                    error!("Failed to delete expired token: {:?}", e);
                }

                return (
                    StatusCode::UNAUTHORIZED,
                    "Token expired and refresh failed. Please authenticate again.".to_string(),
                )
                    .into_response();
            }

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to retrieve token: {}", err),
            )
                .into_response()
        }
    }
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
