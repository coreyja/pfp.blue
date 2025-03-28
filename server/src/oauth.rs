use base64ct::{Base64UrlUnpadded, Encoding};
use cja::jobs::Job;
use color_eyre::eyre::{eyre, WrapErr};
use jsonwebtoken::Algorithm;
use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey, EncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let decoded_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_key_base64,
    )
    .wrap_err_with(|| "Failed to decode base64-encoded public key".to_string())?;

    // Log the first few bytes without revealing the whole key
    let key_preview = if decoded_key.len() > 30 {
        format!("{:?}...", &decoded_key[..30])
    } else {
        format!("{:?}", decoded_key)
    };
    tracing::debug!("Public key starts with: {}", key_preview);

    // Convert the decoded key bytes to a string for PEM parsing
    let key_str = std::str::from_utf8(&decoded_key)
        .wrap_err_with(|| "Failed to convert decoded public key to string")?;

    // Parse the public key from PEM format
    let verifying_key = VerifyingKey::from_public_key_pem(key_str)
        .wrap_err_with(|| format!("Failed to parse public key. Key preview: {}", key_preview))?;

    // Get the public key as an EncodedPoint
    let public_key = PublicKey::from(verifying_key);
    let encoded_point = EncodedPoint::from(public_key);

    // Extract x and y coordinates
    let x_bytes = encoded_point
        .x()
        .ok_or_else(|| eyre!("Failed to extract x coordinate"))
        .wrap_err("Missing x coordinate in public key")?;
    let y_bytes = encoded_point
        .y()
        .ok_or_else(|| eyre!("Failed to extract y coordinate"))
        .wrap_err("Missing y coordinate in public key")?;

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

/// Calculate the JWK thumbprint for the given public key
///
/// This follows RFC 7638 for JWK Thumbprint calculation
pub fn calculate_jwk_thumbprint(public_key_base64: &str) -> cja::Result<String> {
    // First generate the JWK for the public key
    let jwk = generate_jwk(public_key_base64)?;

    // Create the canonical JWK representation with only the required fields in lexicographic order
    let canonical_jwk = serde_json::json!({
        "crv": jwk.crv,
        "kty": jwk.kty,
        "x": jwk.x,
        "y": jwk.y
    });

    // Convert to a compact JSON string without whitespace
    let canonical_json =
        serde_json::to_string(&canonical_jwk).wrap_err("Failed to serialize canonical JWK")?;

    // Calculate SHA-256 hash
    use ring::digest::{digest, SHA256};
    let digest = digest(&SHA256, canonical_json.as_bytes());

    // Base64-URL encode the result
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

    use tempfile::NamedTempFile;

    // Debug info
    let key_preview = if oauth_config.private_key.len() > 10 {
        format!(
            "{}...{}",
            &oauth_config.private_key[..5],
            &oauth_config.private_key[oauth_config.private_key.len() - 5..]
        )
    } else {
        oauth_config.private_key.clone()
    };
    tracing::debug!(
        "Creating client assertion with private key: {}",
        key_preview
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("Failed to get current time")?
        .as_secs();

    // Get the JWK for header
    let jwk = generate_jwk(&oauth_config.public_key)?;

    // Create the JWT header with the key ID
    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.kid = Some(jwk.kid.clone());
    header.typ = Some("JWT".to_string());

    // For Bluesky, the 'aud' should be a fixed value rather than the token endpoint
    // According to the error message, they're expecting a specific value
    let payload = TokenRequestPayload {
        iss: client_id.to_string(),
        sub: client_id.to_string(),
        // Use the configured Bluesky audience or default
        aud: std::env::var("APPVIEW_URL").unwrap_or_else(|_| "https://bsky.social".to_string()),
        jti: uuid::Uuid::new_v4().to_string(),
        exp: now + 300, // 5 minutes in the future
        iat: now,
    };

    // Create a temporary file for the ES256 private key
    let mut key_file =
        NamedTempFile::new().wrap_err("Failed to create temporary file for private key")?;

    // Decode base64-encoded private key
    let decoded_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &oauth_config.private_key,
    )
    .wrap_err("Failed to decode base64-encoded private key")?;

    // Write the decoded PEM-encoded private key to the file
    key_file
        .write_all(&decoded_key)
        .wrap_err("Failed to write private key to temporary file")?;

    // Create a temporary file for the payload
    let mut payload_file =
        NamedTempFile::new().wrap_err("Failed to create temporary file for payload")?;

    // Create payload JSON
    let payload_json = serde_json::to_string(&payload).wrap_err("Failed to serialize payload")?;

    // Write payload to file
    payload_file
        .write_all(payload_json.as_bytes())
        .wrap_err("Failed to write payload to temporary file")?;

    // Create header JSON with proper format for OpenSSL
    // Ensure we're using the exact format expected by Bluesky
    let header_json = serde_json::json!({
        "alg": "ES256",
        "typ": "JWT",
        "kid": jwk.kid
    })
    .to_string();

    // Log the JWT header and payload for debugging
    tracing::debug!("JWT Header: {}", header_json);
    tracing::debug!("JWT Payload: {}", payload_json);

    // Also log the token_endpoint and audience for comparison
    tracing::debug!("Token endpoint: {}", token_endpoint);
    tracing::debug!("JWT audience: {}", payload.aud);

    // Use OpenSSL directly to create the JWT
    // 1. Create Base64URL-encoded header
    let header_b64 = base64_url_encode(header_json.as_bytes());

    // 2. Create Base64URL-encoded payload
    let payload_b64 = base64_url_encode(payload_json.as_bytes());

    // 3. Combine to form the message to sign
    let message = format!("{}.{}", header_b64, payload_b64);

    // 4. Create a temporary file for the message
    let mut message_file =
        NamedTempFile::new().wrap_err("Failed to create temporary file for message")?;
    message_file
        .write_all(message.as_bytes())
        .wrap_err("Failed to write message to temporary file")?;

    // 5. Use OpenSSL to create the signature, but with specific parameters for ES256
    // For ES256, the signature format is different than just the raw digest output
    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-sign")
        .arg(key_file.path())
        // Use the binary DER format
        .arg("-binary")
        .arg(message_file.path())
        .output()
        .wrap_err("Failed to execute OpenSSL for signing")?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(eyre!("OpenSSL signing failed: {}", error));
    }

    // The raw signature from OpenSSL is in ASN.1 DER format
    // We need to convert this to the R+S concatenated format for ES256 JWT
    let signature_der = output.stdout;

    // 6. Convert DER-encoded signature to raw R||S format for JWT
    let signature_raw = match der_signature_to_raw_signature(&signature_der) {
        Ok(sig) => sig,
        Err(e) => {
            return Err(eyre!(
                "Failed to convert DER signature to raw format: {}",
                e
            ))
        }
    };

    // 7. Base64URL-encode the raw signature
    let signature_b64 = base64_url_encode(&signature_raw);

    // 7. Combine to form the complete JWT
    let token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    Ok(token)
}

/// Helper function to create URL-safe base64 encoding without padding
fn base64_url_encode(input: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(input)
}

/// Convert a DER-encoded ECDSA signature to the raw format required for JWT
/// For ES256, the signature must be a 64-byte array containing R and S values (each 32 bytes)
fn der_signature_to_raw_signature(der_signature: &[u8]) -> cja::Result<Vec<u8>> {
    use simple_asn1::{from_der, ASN1Block};

    use color_eyre::eyre::eyre;

    // Parse the DER-encoded signature
    let blocks = from_der(der_signature).wrap_err("Failed to parse DER signature")?;

    // The DER signature should be a SEQUENCE with two INTEGERs (r and s)
    if blocks.len() != 1 {
        return Err(eyre!("Expected 1 ASN.1 block, found {}", blocks.len()));
    }

    // Extract the r and s values from the sequence
    let (r, s) = match &blocks[0] {
        ASN1Block::Sequence(_, items) => {
            if items.len() != 2 {
                return Err(eyre!("Expected 2 items in sequence, found {}", items.len()));
            }

            let r = match &items[0] {
                ASN1Block::Integer(_, r) => r,
                _ => return Err(eyre!("Expected INTEGER for r value, found {:?}", items[0])),
            };

            let s = match &items[1] {
                ASN1Block::Integer(_, s) => s,
                _ => return Err(eyre!("Expected INTEGER for s value, found {:?}", items[1])),
            };

            (r, s)
        }
        _ => return Err(eyre!("Expected SEQUENCE, found {:?}", blocks[0])),
    };

    // Convert BigInt to bytes
    let (_, r_bytes) = r.to_bytes_be(); // to_bytes_be returns (sign, bytes)
    let (_, s_bytes) = s.to_bytes_be();

    // Ensure R and S are each 32 bytes
    let mut result = vec![0u8; 64];

    // Fill result with R value (left-padded with zeros if needed)
    let r_offset = 32 - r_bytes.len();
    if r_offset > 0 {
        // R is shorter than 32 bytes, need padding
        result[r_offset..32].copy_from_slice(&r_bytes);
    } else if r_bytes.len() > 32 {
        // R is longer than 32 bytes, need truncation (shouldn't happen)
        result[..32].copy_from_slice(&r_bytes[r_bytes.len() - 32..]);
    } else {
        // R is exactly 32 bytes
        result[..32].copy_from_slice(&r_bytes);
    }

    // Fill result with S value (left-padded with zeros if needed)
    let s_offset = 32 - s_bytes.len();
    if s_offset > 0 {
        // S is shorter than 32 bytes, need padding
        result[32 + s_offset..].copy_from_slice(&s_bytes);
    } else if s_bytes.len() > 32 {
        // S is longer than 32 bytes, need truncation (shouldn't happen)
        result[32..].copy_from_slice(&s_bytes[s_bytes.len() - 32..]);
    } else {
        // S is exactly 32 bytes
        result[32..].copy_from_slice(&s_bytes);
    }

    Ok(result)
}

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

    // Function removed - not used in codebase

    /// Copy the display name and handle from another token
    #[allow(dead_code)]
    pub fn with_display_name_from(mut self, other: &OAuthTokenSet) -> Self {
        self.display_name = other.display_name.clone();
        self.handle = other.handle.clone();
        self
    }

    // Removed unused methods

    /// Create a new OAuthTokenSet from a TokenResponse with a calculated JWK thumbprint
    pub fn from_token_response_with_jwk(
        response: &TokenResponse,
        did: String,
        public_key: &str,
    ) -> cja::Result<Self> {
        let mut token_set = Self::from_token_response(response.clone(), did);

        // If there's no JWK thumbprint in the response, calculate it
        if token_set.dpop_jkt.is_none() {
            let calculated_jkt = calculate_jwk_thumbprint(public_key)?;
            token_set.dpop_jkt = Some(calculated_jkt);
        }

        Ok(token_set)
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

/// Create a DPoP (Demonstrating Proof-of-Possession) proof JWT for API requests
/// This is required by Bluesky's OAuth implementation
pub fn create_dpop_proof(
    oauth_config: &BlueskyOAuthConfig,
    http_method: &str,
    endpoint_url: &str,
    server_nonce: Option<&str>,
) -> cja::Result<String> {
    // Call the implementation with access token parameter as None
    create_dpop_proof_impl(oauth_config, http_method, endpoint_url, server_nonce, None)
}

/// Create a DPoP proof that includes the access token hash (ath) claim
/// This is needed for some PDS servers that require the ath claim
pub fn create_dpop_proof_with_ath(
    oauth_config: &BlueskyOAuthConfig,
    http_method: &str,
    endpoint_url: &str,
    server_nonce: Option<&str>,
    access_token: &str,
) -> cja::Result<String> {
    // Call the implementation with the access token
    create_dpop_proof_impl(
        oauth_config,
        http_method,
        endpoint_url,
        server_nonce,
        Some(access_token),
    )
}

/// Internal implementation for creating DPoP proofs with or without access token hash
fn create_dpop_proof_impl(
    oauth_config: &BlueskyOAuthConfig,
    http_method: &str,
    endpoint_url: &str,
    server_nonce: Option<&str>,
    access_token: Option<&str>,
) -> cja::Result<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::NamedTempFile;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| eyre!("Failed to get current time: {}", e))?
        .as_secs();

    // Generate JWK for header
    let jwk = generate_jwk(&oauth_config.public_key)?;

    // Create the JWT header with the key ID
    let header_json = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": jwk.kty,
            "crv": jwk.crv,
            "x": jwk.x,
            "y": jwk.y,
            "kid": jwk.kid
        }
    })
    .to_string();

    // Create the DPoP payload according to the spec
    let mut payload_json = serde_json::json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": http_method,
        "htu": endpoint_url,
        "iat": now,
        "exp": now + 300, // 5 minutes in the future
    });

    // Add nonce claim if provided
    if let Some(nonce) = server_nonce {
        payload_json["nonce"] = nonce.to_owned().into();
    }

    // Add ath (access token hash) claim if access token is provided
    if let Some(token) = access_token {
        // Calculate SHA-256 hash of the access token
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hasher.finalize();

        // Base64url encode the hash
        let ath = URL_SAFE_NO_PAD.encode(token_hash);

        // Add the ath claim to the payload
        payload_json["ath"] = ath.into();

        tracing::debug!("Added access token hash (ath) to DPoP proof");
    }

    let payload_json = payload_json.to_string();

    // Log the DPoP JWT components
    tracing::debug!("DPoP Header: {}", header_json);
    tracing::debug!("DPoP Payload: {}", payload_json);

    // 1. Create Base64URL-encoded header
    let header_b64 = base64_url_encode(header_json.as_bytes());

    // 2. Create Base64URL-encoded payload
    let payload_b64 = base64_url_encode(payload_json.as_bytes());

    // 3. Combine to form the message to sign
    let message = format!("{}.{}", header_b64, payload_b64);

    // 4. Create a temporary file for the message
    let mut message_file = NamedTempFile::new()
        .map_err(|e| eyre!("Failed to create temporary file for message: {}", e))?;
    message_file
        .write_all(message.as_bytes())
        .map_err(|e| eyre!("Failed to write message to temporary file: {}", e))?;

    // 5. Create a temporary file for the ES256 private key
    let mut key_file = NamedTempFile::new()
        .map_err(|e| eyre!("Failed to create temporary file for private key: {}", e))?;

    // Decode base64-encoded private key
    let decoded_key = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &oauth_config.private_key,
    ) {
        Ok(key) => key,
        Err(e) => return Err(eyre!("Failed to decode base64-encoded private key: {}", e)),
    };

    // Write the decoded PEM-encoded private key to the file
    key_file
        .write_all(&decoded_key)
        .map_err(|e| eyre!("Failed to write private key to temporary file: {}", e))?;

    // 6. Use OpenSSL to create the signature
    let output = Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-sign")
        .arg(key_file.path())
        .arg("-binary")
        .arg(message_file.path())
        .output()
        .map_err(|e| eyre!("Failed to execute OpenSSL for signing: {}", e))?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(eyre!("OpenSSL signing failed: {}", error));
    }

    // The raw signature from OpenSSL is in ASN.1 DER format
    // We need to convert this to the R+S concatenated format for ES256 JWT
    let signature_der = output.stdout;

    // 7. Convert DER-encoded signature to raw R||S format for JWT
    let signature_raw = match der_signature_to_raw_signature(&signature_der) {
        Ok(sig) => sig,
        Err(e) => {
            return Err(eyre!(
                "Failed to convert DER signature to raw format: {}",
                e
            ))
        }
    };

    // 8. Base64URL-encode the raw signature
    let signature_b64 = base64_url_encode(&signature_raw);

    // 9. Combine to form the complete JWT
    let token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    Ok(token)
}

/// Exchange authorization code for access token
pub async fn exchange_code_for_token(
    oauth_config: &BlueskyOAuthConfig,
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    dpop_nonce: Option<&str>,
) -> cja::Result<TokenResponse> {
    // Create the client assertion JWT
    let client_assertion = create_client_assertion(oauth_config, token_endpoint, client_id)?;

    // Send the token request with retry logic and DPoP nonce handling
    let client = reqwest::Client::new();
    let mut retries = 3;
    let mut last_error = None;
    let mut current_dpop_nonce = dpop_nonce.map(|s| s.to_string());

    // Log the request details for debugging
    tracing::debug!("Token endpoint: {}", token_endpoint);
    tracing::debug!("Client ID: {}", client_id);
    tracing::debug!("Redirect URI: {}", redirect_uri);
    tracing::debug!("Code verifier present: {}", code_verifier.is_some());
    tracing::debug!("Client assertion length: {}", client_assertion.len());

    // Use the token endpoint as is
    tracing::debug!("Using token endpoint: {}", token_endpoint);

    while retries > 0 {
        // Create a fresh DPoP proof for each attempt, using the nonce from the previous response if available
        let dpop_proof = create_dpop_proof(
            oauth_config,
            "POST",
            token_endpoint,
            current_dpop_nonce.as_deref(),
        )?;

        tracing::debug!("DPoP proof length: {}", dpop_proof.len());

        // Build the token request body as a URL-encoded string
        let mut body_parts = vec![
            format!("grant_type={}", urlencoding::encode("authorization_code")),
            format!("code={}", urlencoding::encode(code)),
            format!("redirect_uri={}", urlencoding::encode(redirect_uri)),
            format!(
                "client_assertion_type={}",
                urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            ),
            format!(
                "client_assertion={}",
                urlencoding::encode(&client_assertion)
            ),
            format!("client_id={}", urlencoding::encode(client_id)),
        ];

        // Add code_verifier for PKCE if present
        if let Some(verifier) = code_verifier {
            body_parts.push(format!("code_verifier={}", urlencoding::encode(verifier)));
        }

        // Create the complete request body
        let request_body = body_parts.join("&");
        tracing::debug!("Request body: {}", request_body);

        // Make a completely manual POST request with all parameters in the body
        let response = match client
            .post(token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            // Add the DPoP proof header
            .header("DPoP", &dpop_proof)
            .body(request_body.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                last_error = Some(eyre!("Token request network error: {}", e));
                retries -= 1;
                if retries > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                continue;
            }
        };

        // First, check for a DPoP nonce in the response headers
        let received_nonce = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|h| h.to_str().ok())
            .map(|s| {
                tracing::debug!("Received DPoP-Nonce header: {}", s);
                s.to_string()
            });

        if let Some(nonce) = received_nonce {
            current_dpop_nonce = Some(nonce);
        }

        if response.status().is_success() {
            // Parse the token response
            return response
                .json::<TokenResponse>()
                .await
                .map_err(|e| eyre!("Failed to parse token response: {}", e));
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            // Log detailed error information
            tracing::error!(
                "Token request failed. Status: {}, Error: {}\nRequest URL: {}\nRequest Body: {}",
                status,
                error_text,
                token_endpoint,
                request_body
            );

            // Check if the error is a nonce mismatch, which means we need to retry with the provided nonce
            if error_text.contains("use_dpop_nonce") || error_text.contains("nonce mismatch") {
                tracing::debug!("DPoP nonce error detected, will retry with server nonce");

                // Parse the error response to get the nonce if possible
                if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&error_text) {
                    if let Some(nonce) = error_json.get("dpop_nonce").and_then(|n| n.as_str()) {
                        tracing::debug!("Found nonce in error response: {}", nonce);
                        current_dpop_nonce = Some(nonce.to_string());
                    }
                }

                // Try again with another retry
                retries -= 1;
                if retries > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                continue;
            }

            // Don't retry other 4xx errors (except 429)
            if status.is_client_error() && status.as_u16() != 429 {
                return Err(eyre!("Token request failed: {} - {}", status, error_text));
            }

            last_error = Some(eyre!("Token request failed: {} - {}", status, error_text));
        }

        retries -= 1;
        if retries > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    Err(last_error.unwrap_or_else(|| eyre!("Token request failed after retries")))
}

/// Refresh an OAuth token using the refresh token
pub async fn refresh_token(
    oauth_config: &BlueskyOAuthConfig,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    dpop_nonce: Option<&str>,
) -> cja::Result<TokenResponse> {
    // Create the client assertion JWT
    let client_assertion = create_client_assertion(oauth_config, token_endpoint, client_id)?;

    // Send the token request with retry logic and DPoP nonce handling
    let client = reqwest::Client::new();
    let mut retries = 3;
    let mut last_error = None;
    let mut current_dpop_nonce = dpop_nonce.map(|s| s.to_string());

    // Log the request details for debugging
    tracing::debug!("Token endpoint (refresh): {}", token_endpoint);
    tracing::debug!("Client ID (refresh): {}", client_id);
    tracing::debug!(
        "Client assertion length (refresh): {}",
        client_assertion.len()
    );

    while retries > 0 {
        // Create a fresh DPoP proof for each attempt, using the nonce from the previous response if available
        let dpop_proof = create_dpop_proof(
            oauth_config,
            "POST",
            token_endpoint,
            current_dpop_nonce.as_deref(),
        )?;

        tracing::debug!("DPoP proof length (refresh): {}", dpop_proof.len());

        // Build the token request body as a URL-encoded string
        let body_parts = [
            format!("grant_type={}", urlencoding::encode("refresh_token")),
            format!("refresh_token={}", urlencoding::encode(refresh_token)),
            format!(
                "client_assertion_type={}",
                urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            ),
            format!(
                "client_assertion={}",
                urlencoding::encode(&client_assertion)
            ),
            format!("client_id={}", urlencoding::encode(client_id)),
        ];

        // Create the complete request body
        let request_body = body_parts.join("&");
        tracing::debug!("Refresh token request body: {}", request_body);

        // Send the token request
        let response = match client
            .post(token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            // Add the DPoP proof header
            .header("DPoP", &dpop_proof)
            .body(request_body.clone())
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                last_error = Some(eyre!("Token refresh network error: {}", e));
                retries -= 1;
                if retries > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                continue;
            }
        };

        // First, check for a DPoP nonce in the response headers
        let received_nonce = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|h| h.to_str().ok())
            .map(|s| {
                tracing::debug!("Received DPoP-Nonce header in refresh: {}", s);
                s.to_string()
            });

        if let Some(nonce) = received_nonce {
            current_dpop_nonce = Some(nonce);
        }

        if response.status().is_success() {
            // Parse the token response
            return response
                .json::<TokenResponse>()
                .await
                .map_err(|e| eyre!("Failed to parse refresh token response: {}", e));
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());

            // Log detailed error information
            tracing::error!(
                "Token refresh failed. Status: {}, Error: {}\nRequest URL: {}\nRequest Body: {}",
                status,
                error_text,
                token_endpoint,
                request_body
            );

            // Check if the error is a nonce mismatch, which means we need to retry with the provided nonce
            if error_text.contains("use_dpop_nonce") || error_text.contains("nonce mismatch") {
                tracing::debug!(
                    "DPoP nonce error detected in refresh, will retry with server nonce"
                );

                // Parse the error response to get the nonce if possible
                if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&error_text) {
                    if let Some(nonce) = error_json.get("dpop_nonce").and_then(|n| n.as_str()) {
                        tracing::debug!("Found nonce in refresh error response: {}", nonce);
                        current_dpop_nonce = Some(nonce.to_string());
                    }
                }

                // Try again with another retry
                retries -= 1;
                if retries > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                continue;
            }

            // Don't retry other 4xx errors (except 429)
            if status.is_client_error() && status.as_u16() != 429 {
                return Err(eyre!("Token refresh failed: {} - {}", status, error_text));
            }

            last_error = Some(eyre!("Token refresh failed: {} - {}", status, error_text));
        }

        retries -= 1;
        if retries > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    Err(last_error.unwrap_or_else(|| eyre!("Token refresh failed after retries")))
}

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

/// Database functions for managing OAuth sessions and tokens
pub mod db;

/// Resolve the token endpoint for a DID
pub async fn resolve_token_endpoint_for_did(
    did: &str,
    state: &crate::state::AppState,
) -> cja::Result<String> {
    use tracing::info;

    // First try to get the endpoint from the database
    match crate::routes::bsky::get_token_endpoint_for_did(&state.db, did).await? {
        Some(endpoint) => Ok(endpoint),
        None => {
            // Resolve the PDS endpoint for the token
            let xrpc_client = std::sync::Arc::new(atrium_xrpc_client::reqwest::ReqwestClient::new(
                "https://bsky.social",
            ));

            match atrium_api::types::string::Did::new(did.to_string()) {
                Ok(did_obj) => {
                    match crate::did::resolve_did_to_document(&did_obj, xrpc_client).await {
                        Ok(did_document) => {
                            if let Some(services) = did_document.service.as_ref() {
                                if let Some(pds_service) =
                                    services.iter().find(|s| s.id == "#atproto_pds")
                                {
                                    let pds_endpoint = &pds_service.service_endpoint;
                                    let refresh_endpoint = format!(
                                        "{}/xrpc/com.atproto.server.refreshSession",
                                        pds_endpoint
                                    );
                                    info!(
                                        "Resolved PDS endpoint for refresh: {}",
                                        refresh_endpoint
                                    );
                                    Ok(refresh_endpoint)
                                } else {
                                    // Fallback to bsky.social if no PDS service found
                                    Ok("https://bsky.social/xrpc/com.atproto.server.refreshSession"
                                        .to_string())
                                }
                            } else {
                                // Fallback to bsky.social if no services found
                                Ok("https://bsky.social/xrpc/com.atproto.server.refreshSession"
                                    .to_string())
                            }
                        }
                        Err(_) => {
                            // Fallback to bsky.social on resolution error
                            Ok("https://bsky.social/xrpc/com.atproto.server.refreshSession"
                                .to_string())
                        }
                    }
                }
                Err(_) => {
                    // Fallback to bsky.social on DID parse error
                    Ok("https://bsky.social/xrpc/com.atproto.server.refreshSession".to_string())
                }
            }
        }
    }
}

/// Attempt to refresh a token if it's expired
pub async fn refresh_token_if_needed(
    token: &OAuthTokenSet,
    state: &crate::state::AppState,
    token_endpoint: &str,
) -> cja::Result<Option<OAuthTokenSet>> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // Only refresh if token is expired and we have a refresh token
    if !token.is_expired() || token.refresh_token.is_none() {
        return Ok(None);
    }

    let refresh_token_str = token.refresh_token.as_ref().unwrap();
    let client_id = state.client_id();

    // Try to get the latest DPoP nonce
    let dpop_nonce = match db::get_latest_nonce(state, &token.did).await {
        Ok(nonce) => nonce,
        Err(err) => {
            error!("Failed to get DPoP nonce: {:?}", err);
            None
        }
    };

    // Request a new token
    match refresh_token(
        &state.bsky_oauth,
        token_endpoint,
        &client_id,
        refresh_token_str,
        dpop_nonce.as_deref(),
    )
    .await
    {
        Ok(token_response) => {
            // Create a new token set preserving the user ID and display name
            let new_token = match OAuthTokenSet::from_token_response_with_jwk(
                &token_response,
                token.did.clone(),
                &state.bsky_oauth.public_key,
            ) {
                Ok(new_token) => {
                    // Set user ID, display name, and handle from original token
                    let mut token_with_id = new_token.clone();
                    token_with_id.user_id = token.user_id;
                    token_with_id.display_name = token.display_name.clone();
                    token_with_id.handle = token.handle.clone();
                    token_with_id
                }
                Err(err) => {
                    error!("Failed to create token set with JWK: {:?}", err);
                    // Fallback to standard token creation
                    let mut standard_token =
                        OAuthTokenSet::from_token_response(token_response, token.did.clone());
                    standard_token.user_id = token.user_id;
                    standard_token.display_name = token.display_name.clone();
                    standard_token.handle = token.handle.clone();
                    standard_token
                }
            };

            // Store the new token with encryption
            if let Err(err) = db::store_token(state, &new_token).await {
                error!("Failed to store refreshed token: {:?}", err);
                return Err(eyre!("Failed to store refreshed token: {:?}", err));
            }

            // Also fetch profile to update display name if needed
            if let Err(err) = crate::jobs::UpdateProfileInfoJob::from_token(&new_token)
                .enqueue(state.clone(), "token_refresh".to_string())
                .await
            {
                error!(
                    "Failed to enqueue display name update job after token refresh: {:?}",
                    err
                );
            } else {
                info!(
                    "Queued display name update job after token refresh for {}",
                    new_token.did
                );
            }

            Ok(Some(new_token))
        }
        Err(err) => {
            error!("Failed to refresh token: {:?}", err);
            Err(eyre!("Failed to refresh token: {:?}", err))
        }
    }
}

/// Get a token by DID and refresh it if needed
/// This provides a single entry point for getting a valid token
pub async fn get_valid_token_by_did(
    did: &str,
    state: &crate::state::AppState,
) -> cja::Result<OAuthTokenSet> {
    use color_eyre::eyre::eyre;
    use tracing::{error, info};

    // Get the token from the database with decryption
    let token = match db::get_token(state, did).await? {
        Some(token) => token,
        None => return Err(eyre!("No token found for DID: {}", did)),
    };

    // If token is not expired, just return it
    if !token.is_expired() {
        return Ok(token);
    }

    // If token is expired, try to refresh it
    // First resolve the token endpoint
    let token_endpoint = resolve_token_endpoint_for_did(did, state).await?;

    // Then try to refresh
    match refresh_token_if_needed(&token, state, &token_endpoint).await? {
        Some(refreshed_token) => {
            info!("Token for DID {} was refreshed", did);
            Ok(refreshed_token)
        }
        None => {
            // This shouldn't happen since we already checked the token is expired
            error!("Token wasn't refreshed despite being expired");
            Ok(token) // Return the original token as a fallback
        }
    }
}
