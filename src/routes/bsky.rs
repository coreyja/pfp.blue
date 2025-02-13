use axum::{extract::State, Json};

use crate::state::AppState;

pub async fn client_metadata(state: State<AppState>) -> Json<serde_json::Value> {
    let fqdn = format!("https://{}", state.domain);
    let metadata_url = format!("{fqdn}/oauth/bsky/metadata.json");
    let redirect_uri = format!("{fqdn}/oauth/bsky/callback");

    Json(serde_json::json!({
        "client_id": metadata_url,
        "application_type": "web",
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": ["atproto"],
        "response_types": ["code"],
        "redirect_uris": [redirect_uri],
        "dpop_bound_access_tokens": true,
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": [], // TODO: generate jwk
        "client_name": "pfp.blue",
        "client_uri": fqdn,
        // "logo_uri": todo!(),
        // "tos_uri": todo!(),
        // "policy_uri": todo!(),
    }))
}
