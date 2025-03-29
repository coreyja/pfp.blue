use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// Create a new OAuth session with PKCE
    pub fn new(did: String, state: Option<String>, token_endpoint: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate PKCE code verifier and challenge
        let (code_verifier, code_challenge) = Self::generate_pkce_codes().unwrap_or({
            // Fallback to empty strings if generation fails
            (None, None)
        });

        Self {
            did,
            state,
            token_endpoint,
            created_at: now,
            token_set: None,
            code_verifier,
            code_challenge,
            dpop_nonce: None,
        }
    }

    /// Generate PKCE code verifier and challenge
    fn generate_pkce_codes() -> cja::Result<(Option<String>, Option<String>)> {
        use rand::{thread_rng, RngCore};
        use sha2::{Digest, Sha256};

        // Generate a random code verifier (between 43 and 128 characters)
        let mut code_verifier_bytes = [0u8; 64]; // 64 bytes = 128 chars in hex
        thread_rng().fill_bytes(&mut code_verifier_bytes);

        // Base64-URL encode the verifier
        let code_verifier = Base64UrlUnpadded::encode_string(&code_verifier_bytes);

        // Create code challenge using the S256 method
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let hashed_verifier = hasher.finalize();
        let code_challenge = Base64UrlUnpadded::encode_string(&hashed_verifier);

        Ok((Some(code_verifier), Some(code_challenge)))
    }

    /// Check if this session is expired (older than 1 hour)
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Sessions expire after 1 hour
        self.created_at + 3600 < now
    }
}