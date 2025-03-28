use super::*;
use crate::state::AppState;
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::encryption;

/// Stores a new OAuth session in the database
pub async fn store_session(app_state: &AppState, session: &OAuthSession) -> cja::Result<Uuid> {
    let session_id = Uuid::new_v4();
    
    // Encrypt sensitive data
    let encrypted_code_verifier = match &session.code_verifier {
        Some(verifier) => Some(encryption::encrypt(verifier, &app_state.encryption.key).await?),
        None => None,
    };
    
    let encrypted_code_challenge = match &session.code_challenge {
        Some(challenge) => Some(encryption::encrypt(challenge, &app_state.encryption.key).await?),
        None => None,
    };
    
    let encrypted_dpop_nonce = match &session.dpop_nonce {
        Some(nonce) => Some(encryption::encrypt(nonce, &app_state.encryption.key).await?),
        None => None,
    };

    // Insert the session into the database with encrypted values
    sqlx::query!(
        r#"
        INSERT INTO oauth_sessions (
            id, session_id, did, state, token_endpoint, created_at,
            encrypted_code_verifier, encrypted_code_challenge, encrypted_dpop_nonce
        ) VALUES (DEFAULT, $1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        session_id,
        &session.did,
        session.state.as_deref(),
        &session.token_endpoint,
        session.created_at as i64,
        encrypted_code_verifier.as_deref(),
        encrypted_code_challenge.as_deref(),
        encrypted_dpop_nonce.as_deref()
    )
    .execute(&app_state.db)
    .await?;

    Ok(session_id)
}

/// Retrieves an OAuth session by session ID
pub async fn get_session(app_state: &AppState, session_id: Uuid) -> cja::Result<Option<OAuthSession>> {
    let row = sqlx::query!(
        r#"
        SELECT did, state, token_endpoint, created_at,
               encrypted_code_verifier, encrypted_code_challenge, encrypted_dpop_nonce
        FROM oauth_sessions
        WHERE session_id = $1
        "#,
        session_id
    )
    .fetch_optional(&app_state.db)
    .await?;

    if let Some(row) = row {
        // Decrypt the data from encrypted columns
        let code_verifier = match &row.encrypted_code_verifier {
            Some(encrypted) => Some(encryption::decrypt(encrypted, &app_state.encryption.key).await?),
            None => None,
        };
        
        let code_challenge = match &row.encrypted_code_challenge {
            Some(encrypted) => Some(encryption::decrypt(encrypted, &app_state.encryption.key).await?),
            None => None,
        };
        
        let dpop_nonce = match &row.encrypted_dpop_nonce {
            Some(encrypted) => Some(encryption::decrypt(encrypted, &app_state.encryption.key).await?),
            None => None,
        };

        return Ok(Some(OAuthSession {
            did: row.did,
            state: row.state,
            token_endpoint: row.token_endpoint,
            created_at: row.created_at as u64,
            token_set: None, // Token set is retrieved separately
            code_verifier,
            code_challenge,
            dpop_nonce,
        }));
    }
    
    Ok(None)
}

/// Stores an OAuth token in the database with encryption
pub async fn store_token(app_state: &AppState, token_set: &OAuthTokenSet) -> cja::Result<()> {
    // Check if we need to create a user
    let user_id = if let Some(user_id) = token_set.user_id {
        user_id
    } else {
        // Check if a user already exists for this DID
        let existing_user = crate::user::User::get_by_did(&app_state.db, &token_set.did).await?;

        match existing_user {
            Some(user) => user.user_id,
            None => {
                // Create a new user
                let user = crate::user::User::create(&app_state.db, None, None).await?;
                user.user_id
            }
        }
    };

    // Check if there's an existing token for this DID to preserve the display_name if needed
    let existing_row = if token_set.display_name.is_none() {
        // Only fetch the existing display_name if the new token doesn't have one
        sqlx::query!(
            r#"
            SELECT id, display_name FROM oauth_tokens 
            WHERE did = $1 AND display_name IS NOT NULL
            "#,
            &token_set.did
        )
        .fetch_optional(&app_state.db)
        .await?
    } else {
        None // We already have a display_name, no need to fetch
    };

    let existing_display_name = existing_row
        .as_ref()
        .and_then(|row| row.display_name.clone());
    let display_name_to_use = token_set.display_name.clone().or(existing_display_name);

    // Log whether we're preserving the display_name
    if token_set.display_name.is_none() && display_name_to_use.is_some() {
        tracing::info!(
            "Preserving display_name {:?} for DID {} when updating token",
            display_name_to_use,
            token_set.did
        );
    }

    // Encrypt sensitive token information
    let encrypted_access_token =
        encryption::encrypt(&token_set.access_token, &app_state.encryption.key).await?;
    let encrypted_refresh_token = match &token_set.refresh_token {
        Some(refresh_token) => Some(encryption::encrypt(refresh_token, &app_state.encryption.key).await?),
        None => None,
    };

    // Use upsert (INSERT ... ON CONFLICT ... DO UPDATE) to insert or update the token
    sqlx::query!(
        r#"
        INSERT INTO oauth_tokens (
            did, access_token, token_type, expires_at, refresh_token, scope, dpop_jkt, user_id, display_name, handle
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (did) DO UPDATE SET
            access_token = EXCLUDED.access_token,
            token_type = EXCLUDED.token_type,
            expires_at = EXCLUDED.expires_at,
            refresh_token = EXCLUDED.refresh_token,
            scope = EXCLUDED.scope,
            dpop_jkt = EXCLUDED.dpop_jkt,
            user_id = EXCLUDED.user_id,
            display_name = COALESCE(EXCLUDED.display_name, oauth_tokens.display_name),
            handle = COALESCE(EXCLUDED.handle, oauth_tokens.handle),
            updated_at_utc = NOW()
        "#,
        &token_set.did,
        &encrypted_access_token,
        &token_set.token_type,
        token_set.expires_at as i64,
        encrypted_refresh_token.as_deref(),
        &token_set.scope,
        token_set.dpop_jkt.as_deref(),
        user_id,
        display_name_to_use.as_deref(),
        token_set.handle.as_deref()
    )
    .execute(&app_state.db)
    .await?;

    Ok(())
}

/// Retrieves the OAuth token for a DID, decrypting sensitive data
pub async fn get_token(app_state: &AppState, did: &str) -> cja::Result<Option<OAuthTokenSet>> {
    let row = sqlx::query!(
        r#"
        SELECT access_token, token_type, expires_at, refresh_token, scope, dpop_jkt, user_id, display_name, handle
        FROM oauth_tokens
        WHERE did = $1
        "#,
        did
    )
    .fetch_optional(&app_state.db)
    .await?;

    if let Some(row) = row {
        // Decrypt access token and refresh token
        let access_token = encryption::decrypt(&row.access_token, &app_state.encryption.key).await?;
        let refresh_token = match row.refresh_token {
            Some(ref encrypted_refresh_token) => {
                Some(encryption::decrypt(encrypted_refresh_token, &app_state.encryption.key).await?)
            }
            None => None,
        };

        Ok(Some(OAuthTokenSet {
            did: did.to_string(),
            access_token,
            token_type: row.token_type,
            expires_at: row.expires_at as u64,
            refresh_token,
            scope: row.scope,
            display_name: row.display_name,
            handle: row.handle,
            dpop_jkt: row.dpop_jkt,
            user_id: Some(row.user_id),
        }))
    } else {
        Ok(None)
    }
}

/// Retrieves all tokens for a user, decrypting sensitive data
pub async fn get_tokens_for_user(
    app_state: &AppState,
    user_id: uuid::Uuid,
) -> cja::Result<Vec<OAuthTokenSet>> {
    let encrypted_tokens = sqlx::query!(
        r#"
        SELECT did, access_token, token_type, expires_at, refresh_token, scope, dpop_jkt, user_id, display_name, handle
        FROM oauth_tokens
        WHERE user_id = $1
        ORDER BY updated_at_utc DESC
        "#,
        user_id
    )
    .fetch_all(&app_state.db)
    .await?;

    let mut tokens = Vec::with_capacity(encrypted_tokens.len());

    for row in encrypted_tokens {
        // Decrypt access token and refresh token for each token
        let access_token = encryption::decrypt(&row.access_token, &app_state.encryption.key).await?;
        let refresh_token = match row.refresh_token {
            Some(ref encrypted_refresh_token) => {
                Some(encryption::decrypt(encrypted_refresh_token, &app_state.encryption.key).await?)
            }
            None => None,
        };

        tokens.push(OAuthTokenSet {
            did: row.did,
            access_token,
            token_type: row.token_type,
            expires_at: row.expires_at as u64,
            refresh_token,
            scope: row.scope,
            display_name: row.display_name,
            handle: row.handle,
            dpop_jkt: row.dpop_jkt,
            user_id: Some(row.user_id),
        });
    }

    Ok(tokens)
}

/// Deletes a token for a DID
pub async fn delete_token(pool: &PgPool, did: &str) -> cja::Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_tokens
        WHERE did = $1
        "#,
        did
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Updates the display name for a token
pub async fn update_token_display_name(
    pool: &PgPool,
    did: &str,
    display_name: &str,
) -> cja::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oauth_tokens
        SET display_name = $2, updated_at_utc = NOW()
        WHERE did = $1
        "#,
        did,
        display_name
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Updates the handle for a token
pub async fn update_token_handle(pool: &PgPool, did: &str, handle: &str) -> cja::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oauth_tokens
        SET handle = $2, updated_at_utc = NOW()
        WHERE did = $1
        "#,
        did,
        handle
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Gets the most recent DPoP nonce for a DID
pub async fn get_latest_nonce(app_state: &AppState, did: &str) -> cja::Result<Option<String>> {
    // Find the most recent session for this DID that has a nonce
    let row = sqlx::query!(
        r#"
        SELECT encrypted_dpop_nonce FROM oauth_sessions 
        WHERE did = $1 
        ORDER BY updated_at_utc DESC 
        LIMIT 1
        "#,
        did
    )
    .fetch_optional(&app_state.db)
    .await?;

    if let Some(row) = row {
        // Decrypt the nonce if present
        if let Some(encrypted_nonce) = &row.encrypted_dpop_nonce {
            let nonce = encryption::decrypt(encrypted_nonce, &app_state.encryption.key).await?;
            return Ok(Some(nonce));
        }
    }

    Ok(None)
}

/// Updates a session's DPoP nonce
pub async fn update_session_nonce(app_state: &AppState, session_id: Uuid, nonce: &str) -> cja::Result<()> {
    // Encrypt the nonce
    let encrypted_nonce = encryption::encrypt(nonce, &app_state.encryption.key).await?;
    
    // Update the session with the encrypted nonce
    sqlx::query!(
        r#"
        UPDATE oauth_sessions
        SET encrypted_dpop_nonce = $1, updated_at_utc = NOW()
        WHERE session_id = $2
        "#,
        encrypted_nonce,
        session_id
    )
    .execute(&app_state.db)
    .await?;

    Ok(())
}

pub async fn cleanup_expired_sessions(pool: &PgPool) -> cja::Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Sessions expire after 1 hour
    let expired_timestamp = now - 3600;

    let result = sqlx::query!(
        r#"
        DELETE FROM oauth_sessions
        WHERE created_at < $1
        "#,
        expired_timestamp as i64
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
