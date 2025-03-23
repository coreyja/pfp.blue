use std::io::Cursor;
use std::iter;
use std::sync::Arc;

use age::{x25519::Identity, Decryptor, Encryptor};
use color_eyre::eyre::{eyre, Result};

/// Encrypts a string using age encryption
///
/// This function takes sensitive data and encrypts it using the provided age identity
pub async fn encrypt(data: &str, key: &Arc<Identity>) -> Result<String> {
    let data_vec = data.as_bytes().to_vec();
    // Clone the key to move into the blocking task
    let key_clone = key.clone();

    // Perform encryption in a blocking task since it's CPU intensive
    let encrypted = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        // Create the encryptor with the identity's recipient
        let recipient = key_clone.to_public();
        let recipients = iter::once(&recipient as &dyn age::Recipient);
        let encryptor = Encryptor::with_recipients(recipients).expect("Failed to create encryptor");

        // Encrypt to a Vec<u8>
        let mut encrypted = vec![];
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|e| eyre!("Failed to create encrypted writer: {}", e))?;

        use std::io::Write;
        writer
            .write_all(&data_vec)
            .map_err(|e| eyre!("Failed to write data for encryption: {}", e))?;

        // Close the writer to finish encryption
        writer
            .finish()
            .map_err(|e| eyre!("Failed to finish encryption: {}", e))?;

        Ok(encrypted)
    })
    .await??;

    // Convert the encrypted data to base64 for storage
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted);

    Ok(encoded)
}

/// Decrypts a string that was encrypted with the encrypt function
///
/// This function takes a base64 encoded encrypted string and decrypts it using the provided age identity
pub async fn decrypt(encrypted_base64: &str, key: &Arc<Identity>) -> Result<String> {
    // Decode the base64 data
    let encrypted_data =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted_base64)
            .map_err(|e| eyre!("Failed to decode base64 data: {}", e))?;

    // Clone the key for use in the blocking task
    let key_clone = key.clone();

    // Perform decryption in a blocking task
    let decrypted = tokio::task::spawn_blocking(move || -> Result<String> {
        // Create a cursor for the decryptor to read from
        let cursor = Cursor::new(encrypted_data);

        // Create the decryptor
        let decryptor = match Decryptor::new(cursor) {
            Ok(decryptor) => decryptor,
            Err(e) => return Err(eyre!("Failed to create decryptor: {}", e)),
        };

        // Set up the identities for decryption
        let identities = iter::once(key_clone.as_ref() as &dyn age::Identity);

        // Decrypt the data
        let mut reader = match decryptor.decrypt(identities) {
            Ok(reader) => reader,
            Err(e) => return Err(eyre!("Failed to decrypt data: {}", e)),
        };

        // Read the decrypted data to a string
        let mut decrypted = String::new();
        use std::io::Read;
        reader
            .read_to_string(&mut decrypted)
            .map_err(|e| eyre!("Failed to read decrypted data: {}", e))?;

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

        // Encrypt
        let encrypted = encrypt(original, &key).await.unwrap();

        // Verify it's not the same as the original (it's actually encrypted)
        assert_ne!(encrypted, original);

        // Decrypt
        let decrypted = decrypt(&encrypted, &key).await.unwrap();

        // Verify we got back our original data
        assert_eq!(decrypted, original);
    }
}
