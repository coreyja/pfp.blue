use color_eyre::eyre::eyre;
use color_eyre::eyre::WrapErr;
use std::io::Write;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

use crate::state::BlueskyOAuthConfig;

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
    todo!()
    // use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    // use sha2::{Digest, Sha256};

    // let now = SystemTime::now()
    //     .duration_since(UNIX_EPOCH)
    //     .wrap_err("Failed to get current time")?
    //     .as_secs();

    // // Generate JWK for header
    // let jwk = crate::oauth::jwk::generate_jwk(&oauth_config.public_key)?;

    // // Create the JWT header with the key ID
    // let header_json = serde_json::json!({
    //     "alg": "ES256",
    //     "typ": "dpop+jwt",
    //     "jwk": {
    //         "kty": jwk.kty,
    //         "crv": jwk.crv,
    //         "x": jwk.x,
    //         "y": jwk.y,
    //         "kid": jwk.kid
    //     }
    // })
    // .to_string();

    // // Create the DPoP payload according to the spec
    // let mut payload_json = serde_json::json!({
    //     "jti": uuid::Uuid::new_v4().to_string(),
    //     "htm": http_method,
    //     "htu": endpoint_url,
    //     "iat": now,
    //     "exp": now + 300, // 5 minutes in the future
    // });

    // // Add nonce claim if provided
    // if let Some(nonce) = server_nonce {
    //     payload_json["nonce"] = nonce.to_owned().into();
    // }

    // // Add ath (access token hash) claim if access token is provided
    // if let Some(token) = access_token {
    //     // Calculate SHA-256 hash of the access token
    //     let mut hasher = Sha256::new();
    //     hasher.update(token.as_bytes());
    //     let token_hash = hasher.finalize();

    //     // Base64url encode the hash
    //     let ath = URL_SAFE_NO_PAD.encode(token_hash);

    //     // Add the ath claim to the payload
    //     payload_json["ath"] = ath.into();

    //     tracing::debug!("Added access token hash (ath) to DPoP proof");
    // }

    // let payload_json = payload_json.to_string();

    // // Log the DPoP JWT components
    // tracing::debug!("DPoP Header: {}", header_json);
    // tracing::debug!("DPoP Payload: {}", payload_json);

    // // 1. Create Base64URL-encoded header
    // let header_b64 = base64_url_encode(header_json.as_bytes());

    // // 2. Create Base64URL-encoded payload
    // let payload_b64 = base64_url_encode(payload_json.as_bytes());

    // // 3. Combine to form the message to sign
    // let message = format!("{}.{}", header_b64, payload_b64);

    // // 4. Create a temporary file for the message
    // let mut message_file =
    //     NamedTempFile::new().wrap_err("Failed to create temporary file with message")?;
    // message_file
    //     .write_all(message.as_bytes())
    //     .wrap_err("Failed to write message to temporary file")?;

    // // 5. Create a temporary file for the ES256 private key
    // let mut key_file =
    //     NamedTempFile::new().wrap_err("Failed to create temporary file for private key")?;

    // // Decode base64-encoded private key
    // let decoded_key = base64::Engine::decode(
    //     &base64::engine::general_purpose::STANDARD,
    //     &oauth_config.private_key,
    // )
    // .wrap_err("Failed to decode base64-encoded private key")?;

    // // Write the decoded PEM-encoded private key to the file
    // key_file
    //     .write_all(&decoded_key)
    //     .wrap_err("Failed to write private key to temporary file")?;

    // // 6. Use OpenSSL to create the signature
    // let output = Command::new("openssl")
    //     .arg("dgst")
    //     .arg("-sha256")
    //     .arg("-sign")
    //     .arg(key_file.path())
    //     .arg("-binary")
    //     .arg(message_file.path())
    //     .output()
    //     .wrap_err("Failed to execute OpenSSL for signing")?;

    // if !output.status.success() {
    //     let error = String::from_utf8_lossy(&output.stderr);
    //     return Err(eyre!("OpenSSL signing failed: {}", error));
    // }

    // // The raw signature from OpenSSL is in ASN.1 DER format
    // // We need to convert this to the R+S concatenated format for ES256 JWT
    // let signature_der = output.stdout;

    // // 7. Convert DER-encoded signature to raw R||S format for JWT
    // let signature_raw = der_signature_to_raw_signature(&signature_der)
    //     .wrap_err("Failed to convert DER signature to raw format")?;

    // // 8. Base64URL-encode the raw signature
    // let signature_b64 = base64_url_encode(&signature_raw);

    // // 9. Combine to form the complete JWT
    // let token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    // Ok(token)
}
