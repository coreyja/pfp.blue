use color_eyre::eyre::WrapErr;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT payload for token requests
#[derive(Debug, Serialize)]
pub struct TokenRequestPayload {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub exp: u64,
    pub iat: u64,
}

/// Response from the token endpoint
#[derive(Debug, Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: String,
    /// DPoP confirmation key (JWK thumbprint)
    #[serde(rename = "cnf")]
    pub dpop_confirmation: Option<DPoPConfirmation>,
}

/// DPoP confirmation key in token response
#[derive(Debug, Deserialize, Clone)]
pub struct DPoPConfirmation {
    /// JWK thumbprint
    pub jkt: String,
}

/// Represents a complete set of OAuth tokens with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenSet {
    /// The access token for API requests
    pub access_token: String,
    /// The token type (usually "DPoP" for Bluesky)
    pub token_type: String,
    /// When the access token expires (as Unix timestamp)
    pub expires_at: u64,
    /// Refresh token for obtaining a new access token
    pub refresh_token: Option<String>,
    /// The scopes granted to this token
    pub scope: String,
    /// The Bluesky DID this token is associated with
    pub did: String,
    /// The Bluesky display name associated with this DID
    pub display_name: Option<String>,
    /// The Bluesky handle (username with domain) associated with this DID
    pub handle: Option<String>,
    /// DPoP confirmation key (JWK thumbprint)
    pub dpop_jkt: Option<String>,
    /// User ID that owns this token
    pub user_id: Option<uuid::Uuid>,
}

impl OAuthTokenSet {
    /// Create a new OAuthTokenSet from a TokenResponse
    pub fn from_token_response(response: TokenResponse, did: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .wrap_err("Failed to calculate duration since epoch")
            .unwrap_or_default()
            .as_secs();

        Self {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_at: now + response.expires_in,
            refresh_token: response.refresh_token,
            scope: response.scope,
            did,
            display_name: None, // Will be updated later when we fetch profile data
            handle: None,       // Will be updated later when we fetch profile data
            dpop_jkt: response.dpop_confirmation.map(|cnf| cnf.jkt),
            user_id: None,
        }
    }

    /// Create a new OAuthTokenSet from a TokenResponse with a calculated JWK thumbprint
    pub fn from_token_response_with_jwk(
        response: &TokenResponse,
        did: String,
        public_key: &str,
    ) -> cja::Result<Self> {
        let mut token_set = Self::from_token_response(response.clone(), did);

        // If there's no JWK thumbprint in the response, calculate it
        if token_set.dpop_jkt.is_none() {
            let calculated_jkt = crate::oauth::jwk::calculate_jwk_thumbprint(public_key)?;
            token_set.dpop_jkt = Some(calculated_jkt);
        }

        Ok(token_set)
    }

    /// Check if the access token is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .wrap_err("Failed to calculate duration since epoch")
            .unwrap_or_default()
            .as_secs();

        // Consider tokens expired 30 seconds before actual expiration
        // to account for clock skew and network latency
        self.expires_at < now + 30
    }
}
