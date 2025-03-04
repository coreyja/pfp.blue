use base64ct::{Base64UrlUnpadded, Encoding};
use color_eyre::eyre::eyre;
use jsonwebtoken::{Algorithm, EncodingKey};
use p256::{
    ecdsa::VerifyingKey,
    pkcs8::DecodePublicKey,
    EncodedPoint, PublicKey,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::state::BlueskyOAuthConfig;


#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
}

/// Generate a JWK from a base64-encoded public key
pub fn generate_jwk(public_key_base64: &str) -> cja::Result<Jwk> {
    // Decode the base64-encoded public key
    let decoded_key = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, public_key_base64) {
        Ok(key) => key,
        Err(e) => return Err(eyre!("Failed to decode base64-encoded public key: {}", e)),
    };
    
    // Log the first few bytes without revealing the whole key
    let key_preview = if decoded_key.len() > 30 {
        format!("{:?}...", &decoded_key[..30])
    } else {
        format!("{:?}", decoded_key)
    };
    tracing::debug!("Public key starts with: {}", key_preview);
    
    // Convert the decoded key bytes to a string for PEM parsing
    let key_str = std::str::from_utf8(&decoded_key)
        .map_err(|e| eyre!("Failed to convert decoded public key to string: {}", e))?;
    
    // Parse the public key from PEM format
    let verifying_key = VerifyingKey::from_public_key_pem(key_str)
        .map_err(|e| eyre!("Failed to parse public key: {}. Key preview: {}", e, key_preview))?;
    
    // Get the public key as an EncodedPoint
    let public_key = PublicKey::from(verifying_key);
    let encoded_point = EncodedPoint::from(public_key);
    
    // Extract x and y coordinates
    let x_bytes = encoded_point.x().ok_or_else(|| eyre!("Failed to extract x coordinate"))?;
    let y_bytes = encoded_point.y().ok_or_else(|| eyre!("Failed to extract y coordinate"))?;
    
    // Base64-URL encode the coordinates
    let x = Base64UrlUnpadded::encode_string(x_bytes);
    let y = Base64UrlUnpadded::encode_string(y_bytes);
    
    // Generate a unique ID for the key
    let key_id = generate_key_id(&x, &y)?;
    
    Ok(Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x,
        y,
        kid: key_id,
        alg: Some("ES256".to_string()),
        use_: Some("sig".to_string()),
        key_ops: Some(vec!["verify".to_string()]),
    })
}

/// Generate a key ID from the key's coordinates
fn generate_key_id(x: &str, y: &str) -> cja::Result<String> {
    use ring::digest::{Context, SHA256};
    
    let mut context = Context::new(&SHA256);
    context.update(x.as_bytes());
    context.update(y.as_bytes());
    let digest = context.finish();
    
    Ok(Base64UrlUnpadded::encode_string(digest.as_ref()))
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ClientMetadata {
    pub client_id: String,
    pub application_type: String,
    pub grant_types: Vec<String>,
    pub scope: Vec<String>,
    pub response_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub dpop_bound_access_tokens: bool,
    pub token_endpoint_auth_method: String,
    pub token_endpoint_auth_signing_alg: String,
    pub jwks: Vec<Jwk>,
    pub client_name: String,
    pub client_uri: String,
}

#[derive(Debug, Serialize)]
pub struct TokenRequestPayload {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub exp: u64,
    pub iat: u64,
}

/// Create a client assertion JWT for OAuth token requests
pub fn create_client_assertion(
    oauth_config: &BlueskyOAuthConfig,
    token_endpoint: &str,
    client_id: &str,
) -> cja::Result<String> {
    use std::io::Write;
    use std::process::Command;
    use std::str;
    use tempfile::NamedTempFile;
    
    // Debug info
    let key_preview = if oauth_config.private_key.len() > 10 {
        format!("{}...{}", &oauth_config.private_key[..5], &oauth_config.private_key[oauth_config.private_key.len()-5..])
    } else {
        oauth_config.private_key.clone()
    };
    tracing::debug!("Creating client assertion with private key: {}", key_preview);
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| eyre!("Failed to get current time: {}", e))?
        .as_secs();
    
    // Get the JWK for header
    let jwk = generate_jwk(&oauth_config.public_key)?;
    
    // Create the JWT header with the key ID
    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some(jwk.kid.clone());
    header.typ = Some("JWT".to_string());
    
    let payload = TokenRequestPayload {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        aud: token_endpoint.to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        exp: now + 300, // 5 minutes in the future
        iat: now,
    };
    
    // Create a temporary file for the ES256 private key
    let mut key_file = NamedTempFile::new()
        .map_err(|e| eyre!("Failed to create temporary file for private key: {}", e))?;
    
    // Decode base64-encoded private key
    let decoded_key = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &oauth_config.private_key) {
        Ok(key) => key,
        Err(e) => return Err(eyre!("Failed to decode base64-encoded private key: {}", e)),
    };
    
    // Write the decoded PEM-encoded private key to the file
    key_file.write_all(&decoded_key)
        .map_err(|e| eyre!("Failed to write private key to temporary file: {}", e))?;
    
    // Create a temporary file for the payload
    let mut payload_file = NamedTempFile::new()
        .map_err(|e| eyre!("Failed to create temporary file for payload: {}", e))?;
    
    // Create payload JSON
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| eyre!("Failed to serialize payload: {}", e))?;
    
    // Write payload to file
    payload_file.write_all(payload_json.as_bytes())
        .map_err(|e| eyre!("Failed to write payload to temporary file: {}", e))?;
    
    // Create header JSON with proper format for OpenSSL
    let header_json = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": jwk.kid
    }).to_string();
    
    // Use OpenSSL directly to create the JWT
    // 1. Create Base64URL-encoded header
    let header_b64 = base64_url_encode(header_json.as_bytes());
    
    // 2. Create Base64URL-encoded payload
    let payload_b64 = base64_url_encode(payload_json.as_bytes());
    
    // 3. Combine to form the message to sign
    let message = format!("{}.{}", header_b64, payload_b64);
    
    // 4. Create a temporary file for the message
    let mut message_file = NamedTempFile::new()
        .map_err(|e| eyre!("Failed to create temporary file for message: {}", e))?;
    message_file.write_all(message.as_bytes())
        .map_err(|e| eyre!("Failed to write message to temporary file: {}", e))?;
    
    // 5. Use OpenSSL to create the signature
    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-sign")
        .arg(key_file.path())
        .arg(message_file.path())
        .output()
        .map_err(|e| eyre!("Failed to execute OpenSSL for signing: {}", e))?;
    
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(eyre!("OpenSSL signing failed: {}", error));
    }
    
    // 6. Base64URL-encode the signature
    let signature_b64 = base64_url_encode(&output.stdout);
    
    // 7. Combine to form the complete JWT
    let token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);
    
    Ok(token)
}

/// Helper function to create URL-safe base64 encoding without padding
fn base64_url_encode(input: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(input)
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// Represents a complete set of OAuth tokens with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTokenSet {
    /// The access token for API requests
    pub access_token: String,
    /// The token type (usually "Bearer")
    pub token_type: String,
    /// When the access token expires (as Unix timestamp)
    pub expires_at: u64,
    /// Refresh token for obtaining a new access token
    pub refresh_token: Option<String>,
    /// The scopes granted to this token
    pub scope: String,
    /// The Bluesky DID this token is associated with
    pub did: String,
}

impl OAuthTokenSet {
    /// Create a new OAuthTokenSet from a TokenResponse
    pub fn from_token_response(response: TokenResponse, did: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_at: now + response.expires_in,
            refresh_token: response.refresh_token,
            scope: response.scope,
            did,
        }
    }
    
    /// Check if the access token is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        // Consider tokens expired 30 seconds before actual expiration
        // to account for clock skew and network latency
        self.expires_at < now + 30
    }
}

/// Exchange authorization code for access token
pub async fn exchange_code_for_token(
    oauth_config: &BlueskyOAuthConfig,
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> cja::Result<TokenResponse> {
    // Create the client assertion JWT
    let client_assertion = create_client_assertion(oauth_config, token_endpoint, client_id)?;
    
    // Build the token request
    let mut params = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        ("client_assertion", &client_assertion),
    ];
    
    // Add code_verifier for PKCE if present
    if let Some(verifier) = code_verifier {
        params.push(("code_verifier", verifier));
    }
    
    // Send the token request with retry logic
    let client = reqwest::Client::new();
    let mut retries = 3;
    let mut last_error = None;
    
    while retries > 0 {
        match client
            .post(token_endpoint)
            .form(&params)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    // Parse the token response
                    return response.json::<TokenResponse>().await
                        .map_err(|e| eyre!("Failed to parse token response: {}", e).into());
                } else {
                    let status = response.status();
                    let error_text = response.text().await
                        .unwrap_or_else(|_| "Failed to read error response".to_string());
                        
                    // Don't retry 4xx errors (except 429)
                    if status.is_client_error() && status.as_u16() != 429 {
                        return Err(eyre!("Token request failed: {} - {}", status, error_text).into());
                    }
                    
                    last_error = Some(eyre!("Token request failed: {} - {}", status, error_text));
                }
            },
            Err(e) => {
                last_error = Some(eyre!("Token request network error: {}", e));
            }
        }
        
        retries -= 1;
        if retries > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    
    Err(last_error.unwrap_or_else(|| eyre!("Token request failed after retries")).into())
}

/// Refresh an OAuth token using the refresh token
pub async fn refresh_token(
    oauth_config: &BlueskyOAuthConfig,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
) -> cja::Result<TokenResponse> {
    // Create the client assertion JWT
    let client_assertion = create_client_assertion(oauth_config, token_endpoint, client_id)?;
    
    // Build the token request
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        ("client_assertion", &client_assertion),
    ];
    
    // Send the token request
    let client = reqwest::Client::new();
    let response = client
        .post(token_endpoint)
        .form(&params)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;
    
    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(eyre!("Token refresh failed: {}", error_text).into());
    }
    
    // Parse the token response
    let token_response = response.json::<TokenResponse>().await?;
    
    Ok(token_response)
}

/// Represents the data stored in a session during the OAuth flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthSession {
    /// The user's DID
    pub did: String,
    /// Original redirect URI provided to the authorize endpoint
    pub redirect_uri: Option<String>,
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
}

impl OAuthSession {
    /// Create a new OAuth session with PKCE
    pub fn new(
        did: String,
        redirect_uri: Option<String>,
        state: Option<String>,
        token_endpoint: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        // Generate PKCE code verifier and challenge
        let (code_verifier, code_challenge) = Self::generate_pkce_codes().unwrap_or_else(|_| {
            // Fallback to empty strings if generation fails
            (None, None)
        });
            
        Self {
            did,
            redirect_uri,
            state,
            token_endpoint,
            created_at: now,
            token_set: None,
            code_verifier,
            code_challenge,
        }
    }
    
    /// Generate PKCE code verifier and challenge
    fn generate_pkce_codes() -> cja::Result<(Option<String>, Option<String>)> {
        use rand::{rngs::OsRng, RngCore};
        use sha2::{Digest, Sha256};
        
        // Generate a random code verifier (between 43 and 128 characters)
        let mut code_verifier_bytes = [0u8; 64]; // 64 bytes = 128 chars in hex
        OsRng.fill_bytes(&mut code_verifier_bytes);
        
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
    
    /// Set the token set for this session
    pub fn set_token_set(&mut self, token_set: OAuthTokenSet) {
        self.token_set = Some(token_set);
    }
}

/// Database functions for managing OAuth sessions and tokens
pub mod db {
    use super::*;
    use sqlx::{PgPool, Row};
    use uuid::Uuid;
    
    /// Stores a new OAuth session in the database
    pub async fn store_session(pool: &PgPool, session: &OAuthSession) -> cja::Result<Uuid> {
        let session_id = Uuid::new_v4();
        
        // Store PKCE data in the data JSONB field
        let data = serde_json::json!({
            "code_verifier": session.code_verifier,
            "code_challenge": session.code_challenge
        });
        
        sqlx::query(
            r#"
            INSERT INTO oauth_sessions (
                session_id, did, redirect_uri, state, token_endpoint, created_at, data
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(session_id)
        .bind(&session.did)
        .bind(&session.redirect_uri)
        .bind(&session.state)
        .bind(&session.token_endpoint)
        .bind(session.created_at as i64)
        .bind(data)
        .execute(pool)
        .await?;
        
        Ok(session_id)
    }
    
    /// Retrieves an OAuth session by session ID
    pub async fn get_session(pool: &PgPool, session_id: Uuid) -> cja::Result<Option<OAuthSession>> {
        let row = sqlx::query(
            r#"
            SELECT did, redirect_uri, state, token_endpoint, created_at, data
            FROM oauth_sessions
            WHERE session_id = $1
            "#
        )
        .bind(session_id)
        .fetch_optional(pool)
        .await?;
        
        Ok(row.map(|row| {
            // Extract PKCE data from the JSONB field
            let data: Option<serde_json::Value> = row.get("data");
            let code_verifier = data
                .as_ref()
                .and_then(|d| d.get("code_verifier"))
                .and_then(|v| v.as_str())
                .map(String::from);
                
            let code_challenge = data
                .as_ref()
                .and_then(|d| d.get("code_challenge"))
                .and_then(|v| v.as_str())
                .map(String::from);
            
            OAuthSession {
                did: row.get("did"),
                redirect_uri: row.get("redirect_uri"),
                state: row.get("state"),
                token_endpoint: row.get("token_endpoint"),
                created_at: row.get::<i64, _>("created_at") as u64,
                token_set: None, // Token set is retrieved separately
                code_verifier,
                code_challenge,
            }
        }))
    }
    
    /// Stores an OAuth token in the database
    pub async fn store_token(pool: &PgPool, token_set: &OAuthTokenSet) -> cja::Result<()> {
        // First, deactivate any existing active tokens for this DID
        sqlx::query(
            r#"
            UPDATE oauth_tokens
            SET is_active = FALSE, updated_at_utc = NOW()
            WHERE did = $1 AND is_active = TRUE
            "#
        )
        .bind(&token_set.did)
        .execute(pool)
        .await?;
        
        // Then insert the new token
        sqlx::query(
            r#"
            INSERT INTO oauth_tokens (
                did, access_token, token_type, expires_at, refresh_token, scope
            ) VALUES ($1, $2, $3, $4, $5, $6)
            "#
        )
        .bind(&token_set.did)
        .bind(&token_set.access_token)
        .bind(&token_set.token_type)
        .bind(token_set.expires_at as i64)
        .bind(&token_set.refresh_token)
        .bind(&token_set.scope)
        .execute(pool)
        .await?;
        
        Ok(())
    }
    
    /// Retrieves the most recent active OAuth token for a DID
    pub async fn get_token(pool: &PgPool, did: &str) -> cja::Result<Option<OAuthTokenSet>> {
        let row = sqlx::query(
            r#"
            SELECT access_token, token_type, expires_at, refresh_token, scope
            FROM oauth_tokens
            WHERE did = $1 AND is_active = TRUE
            ORDER BY created_at_utc DESC
            LIMIT 1
            "#
        )
        .bind(did)
        .fetch_optional(pool)
        .await?;
        
        Ok(row.map(|row| OAuthTokenSet {
            did: did.to_string(),
            access_token: row.get("access_token"),
            token_type: row.get("token_type"),
            expires_at: row.get::<i64, _>("expires_at") as u64,
            refresh_token: row.get("refresh_token"),
            scope: row.get("scope"),
        }))
    }
    
    /// Marks a token as inactive
    pub async fn deactivate_token(pool: &PgPool, did: &str) -> cja::Result<()> {
        sqlx::query(
            r#"
            UPDATE oauth_tokens
            SET is_active = FALSE, updated_at_utc = NOW()
            WHERE did = $1 AND is_active = TRUE
            "#
        )
        .bind(did)
        .execute(pool)
        .await?;
        
        Ok(())
    }
    
    /// Cleans up expired sessions
    pub async fn cleanup_expired_sessions(pool: &PgPool) -> cja::Result<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        // Sessions expire after 1 hour
        let expired_timestamp = now - 3600;
        
        let result = sqlx::query(
            r#"
            DELETE FROM oauth_sessions
            WHERE created_at < $1
            "#
        )
        .bind(expired_timestamp as i64)
        .execute(pool)
        .await?;
        
        Ok(result.rows_affected())
    }
}