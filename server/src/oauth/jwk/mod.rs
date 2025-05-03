use std::collections::BTreeSet;

use color_eyre::eyre::{eyre, WrapErr};
use jose_jwk::{jose_jwa::Algorithm, Ec, EcCurves, Jwk, Key, Operations, Parameters};
use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey, EncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};

// /// JSON Web Key data structure
// #[derive(Debug, Serialize, Deserialize)]
// pub struct Jwk {
//     pub kty: String,
//     pub crv: String,
//     pub x: String,
//     pub y: String,
//     pub kid: String,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub alg: Option<String>,
//     #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
//     pub use_: Option<String>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub key_ops: Option<Vec<String>>,
// }

/// Generate a JWK from a base64-encoded public key
pub fn generate_jwk(public_key_base64: &str) -> cja::Result<Jwk> {
    // Decode the base64-encoded public key
    let decoded_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_key_base64,
    )
    .wrap_err("Failed to decode base64-encoded public key")?;

    // Log the first few bytes without revealing the whole key
    let key_preview = if decoded_key.len() > 30 {
        format!("{:?}...", &decoded_key[..30])
    } else {
        format!("{:?}", decoded_key)
    };
    tracing::debug!("Public key starts with: {}", key_preview);
    dbg!(&decoded_key);

    // Convert the decoded key bytes to a string for PEM parsing
    let key_str = std::str::from_utf8(&decoded_key)
        .wrap_err("Failed to convert decoded public key to string")?;

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

    // Generate a unique ID for the key
    let key_id = crate::oauth::new::generate_key_id(x_bytes, y_bytes)?;

    let mut ops = BTreeSet::new();
    ops.insert(Operations::Verify);
    Ok(Jwk {
        key: Key::Ec(Ec {
            crv: EcCurves::P256,
            x: x_bytes.to_vec().into(),
            y: y_bytes.to_vec().into(),
            d: None,
        }),
        prm: Parameters {
            kid: Some(key_id),
            alg: Some(Algorithm::Signing(jose_jwk::jose_jwa::Signing::Es256)),
            ops: Some(ops),
            cls: Some(jose_jwk::Class::Signing),
            ..Default::default()
        },
    })
}

/// Calculate the JWK thumbprint for the given public key
///
/// This follows RFC 7638 for JWK Thumbprint calculation
pub fn calculate_jwk_thumbprint(public_key_base64: &str) -> cja::Result<String> {
    // // First generate the JWK for the public key
    // let jwk = generate_jwk(public_key_base64)?;

    // // Create the canonical JWK representation with only the required fields in lexicographic order
    // let canonical_jwk = todo!();

    // // Convert to a compact JSON string without whitespace
    // let canonical_json =
    //     serde_json::to_string(&canonical_jwk).wrap_err("Failed to serialize canonical JWK")?;

    // // Calculate SHA-256 hash
    // use ring::digest::{digest, SHA256};
    // let digest = digest(&SHA256, canonical_json.as_bytes());

    // // Base64-URL encode the result
    // Ok(Base64UrlUnpadded::encode_string(digest.as_ref()))
    todo!()
}

/// Client metadata for OAuth client registration
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
