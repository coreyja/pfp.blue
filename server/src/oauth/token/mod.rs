use serde::{Deserialize, Serialize};

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
}
