use crate::errors::{ServerResult, WithStatus};
use axum::{extract::State, http::StatusCode, Json};
use color_eyre::eyre::WrapErr;
use tracing::info;

use crate::{oauth, state::AppState};

pub async fn client_metadata(
    state: State<AppState>,
) -> ServerResult<Json<serde_json::Value>, StatusCode> {
    let fqdn = format!("{}://{}", state.protocol, state.domain);
    let metadata_url = state.client_id();
    let redirect_uri = state.redirect_uri();

    // Generate JWK for the client metadata
    let jwk = oauth::generate_jwk(&state.bsky_oauth.public_key)
        .wrap_err("Failed to generate JWK")
        .with_status(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Add the debug info for what we're sending
    info!("Sending client metadata with JWK: {:?}", jwk);

    // Craft the metadata according to OpenID Connect Dynamic Client Registration
    let metadata = serde_json::json!({
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
    });

    Ok(Json(metadata))
}
