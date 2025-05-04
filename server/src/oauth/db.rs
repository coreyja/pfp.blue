use super::*;
use crate::state::AppState;
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::encryption;

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
        let access_token =
            encryption::decrypt(&row.access_token, &app_state.encryption.key).await?;
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
        let access_token =
            encryption::decrypt(&row.access_token, &app_state.encryption.key).await?;
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
pub async fn update_token_display_name_and_handle(
    pool: &PgPool,
    did: &str,
    display_name: Option<&str>,
    handle: Option<&str>,
) -> cja::Result<()> {
    sqlx::query!(
        r#"
        UPDATE oauth_tokens
        SET display_name = $2, handle = $3, updated_at_utc = NOW()
        WHERE did = $1
        "#,
        did,
        display_name,
        handle
    )
    .execute(pool)
    .await?;

    Ok(())
}
