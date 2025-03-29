use color_eyre::eyre::{eyre, WrapErr};
use simple_asn1::{from_der, ASN1Block};

/// Helper function to create URL-safe base64 encoding without padding
pub fn base64_url_encode(input: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(input)
}

/// Convert a DER-encoded ECDSA signature to the raw format required for JWT
/// For ES256, the signature must be a 64-byte array containing R and S values (each 32 bytes)
pub fn der_signature_to_raw_signature(der_signature: &[u8]) -> cja::Result<Vec<u8>> {
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