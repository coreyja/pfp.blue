use std::io::{Read, Write};
use std::sync::Arc;

use age::armor::{ArmoredReader, ArmoredWriter};
use age::encrypt_and_armor;
use age::{x25519::Identity, Decryptor, Encryptor};
use color_eyre::eyre::{eyre, Result};

/// Encrypts a string using age encryption with ASCII armor
///
/// This function takes sensitive data and encrypts it using the provided age identity
/// The result is armored (ASCII encoded) for easy storage
pub async fn encrypt(data: &str, key: &Arc<Identity>) -> Result<String> {
    let data_vec = data.as_bytes().to_vec();
    let recipient = key.to_public();

    // Perform encryption in a blocking task since it's CPU intensive
    let armored = tokio::task::spawn_blocking(move || -> Result<String> {
        let result = encrypt_and_armor(&recipient, &data_vec)?;

        Ok(result)
    })
    .await??;

    Ok(armored)
}

/// Decrypts a string that was encrypted with the encrypt function
///
/// This function takes an armored encrypted string and decrypts it using the provided age identity
pub async fn decrypt(armored_data: &str, key: &Arc<Identity>) -> Result<String> {
    // Clone the key and data for use in the blocking task
    let key_clone = key.clone();
    let armored_data_clone = armored_data.to_string();

    // Perform decryption in a blocking task
    let decrypted = tokio::task::spawn_blocking(move || -> Result<String> {
        let decrypted = age::decrypt(key_clone.as_ref(), armored_data_clone.as_bytes())?;
        let decrypted = String::from_utf8(decrypted)?;

        Ok(decrypted)
    })
    .await??;

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        // Generate a test identity
        let identity = Identity::generate();
        let key = Arc::new(identity);

        // Original data
        let original = "This is sensitive data that needs to be encrypted";

        // Encrypt with armoring
        let encrypted = encrypt(original, &key).await.unwrap();

        // Verify it's not the same as the original (it's encrypted and armored)
        assert_ne!(encrypted, original);

        // Decrypt
        let decrypted = decrypt(&encrypted, &key).await.unwrap();

        // Verify we got back our original data
        assert_eq!(decrypted, original);
    }
}
