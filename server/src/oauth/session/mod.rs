use serde::{Deserialize, Serialize};

use crate::oauth::token::OAuthTokenSet;

/// Represents the data stored in a session during the OAuth flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    /// The user's DID
    pub did: String,
    /// Original redirect URI provided to the authorize endpoint
    // pub redirect_uri: Option<String>,
    /// State parameter passed to the authorize endpoint
    pub state: Option<String>,
    /// The authorization server's token endpoint
    pub token_endpoint: String,
    /// The timestamp when this session was created
    pub created_at: u64,
    /// Optional token set if the OAuth flow has completed
    pub token_set: Option<OAuthTokenSet>,
    /// PKCE code verifier - the original random string
    pub code_verifier: Option<String>,
    /// PKCE code challenge - the hashed and encoded verifier
    pub code_challenge: Option<String>,
    /// DPoP nonce from the server
    pub dpop_nonce: Option<String>,
}

impl OAuthSession {
}
