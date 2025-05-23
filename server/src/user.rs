use chrono::{DateTime, Utc};
use color_eyre::eyre::Context as _;
use sqlx::postgres::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::{encryption, oauth::OAuthTokenSet, state::AppState};

/// Represents a user in the system
#[derive(Debug, Clone)]
// Fields needed for database operations
pub struct User {
    /// Unique user ID (matches database column 'id')
    pub user_id: Uuid,
    /// Optional username
    pub username: Option<String>,
    /// Whether this user has admin privileges
    pub is_admin: bool,
    /// When the user was created
    #[allow(dead_code)]
    pub created_at_utc: DateTime<Utc>,
    /// When the user was last updated
    #[allow(dead_code)]
    pub updated_at_utc: DateTime<Utc>,
}

/// Represents a session for authenticated users
#[derive(Debug, Clone)]
// Fields needed for database operations
pub struct Session {
    /// Unique session ID (used in cookies)
    pub id: Uuid,
    /// The user this session belongs to
    pub user_id: Uuid,
    /// When this session expires
    pub expires_at: DateTime<Utc>,
    /// Whether this session is active
    pub is_active: bool,
    /// ID of the primary OAuth token for this session (if set)
    pub primary_token_id: Option<Uuid>,
    /// When the session was created
    #[allow(dead_code)]
    pub created_at_utc: DateTime<Utc>,
    /// When the session was last updated
    pub updated_at_utc: DateTime<Utc>,
}

impl User {
    /// Get a user by their ID
    pub async fn get_by_id(pool: &PgPool, user_id: Uuid) -> cja::Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT id, username, is_admin, created_at_utc, updated_at_utc 
            FROM users WHERE id = $1
            "#,
            user_id
        )
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            user_id: r.id,
            username: r.username,
            is_admin: r.is_admin,
            created_at_utc: r.created_at_utc,
            updated_at_utc: r.updated_at_utc,
        }))
    }

    /// Create a new user with optional username and email
    pub async fn create(pool: &PgPool, username: Option<String>) -> cja::Result<User> {
        let row = sqlx::query!(
            r#"
            INSERT INTO users (username, is_admin)
            VALUES ($1, false)
            RETURNING id, username, is_admin, created_at_utc, updated_at_utc
            "#,
            username,
        )
        .fetch_one(pool)
        .await?;

        info!("Created new user with ID: {}", row.id);

        Ok(User {
            user_id: row.id,
            username: row.username,
            is_admin: row.is_admin,
            created_at_utc: row.created_at_utc,
            updated_at_utc: row.updated_at_utc,
        })
    }

    /// Get a user by the DID of one of their OAuth tokens
    pub async fn get_by_did(pool: &PgPool, did: &str) -> cja::Result<Option<User>> {
        let row = sqlx::query!(
            r#"
            SELECT u.id, u.username, u.is_admin, u.created_at_utc, u.updated_at_utc FROM users u
            JOIN oauth_tokens ot ON u.id = ot.user_id
            WHERE ot.did = $1
            LIMIT 1
            "#,
            did
        )
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            user_id: r.id,
            username: r.username,
            is_admin: r.is_admin,
            created_at_utc: r.created_at_utc,
            updated_at_utc: r.updated_at_utc,
        }))
    }

    // Removed unused methods - can be added back when needed
}

impl Session {
    /// Create a new session for a user
    pub async fn create(
        pool: &PgPool,
        user_id: Uuid,
        duration_days: i64,
        primary_token_id: Option<Uuid>,
    ) -> cja::Result<Session> {
        // Calculate expiration time
        let expires_at = Utc::now() + chrono::Duration::days(duration_days);

        let row = sqlx::query_as!(
            Session,
            r#"
            INSERT INTO sessions (user_id, expires_at, primary_token_id)
            VALUES ($1, $2, $3)
            RETURNING id, user_id, expires_at, is_active, primary_token_id, created_at_utc, updated_at_utc
            "#,
            user_id,
            expires_at,
            primary_token_id
        )
        .fetch_one(pool)
        .await?;

        info!(
            "Created new session {} for user {} expiring at {}",
            row.id, user_id, expires_at
        );

        Ok(row)
    }

    /// Get a session by its ID
    pub async fn get_by_id(pool: &PgPool, session_id: Uuid) -> cja::Result<Option<Session>> {
        let row = sqlx::query_as!(
            Session,
            r#"
            SELECT id, user_id, expires_at, is_active, primary_token_id, created_at_utc, updated_at_utc
            FROM sessions WHERE id = $1
            "#,
            session_id
        )
        .fetch_optional(pool)
        .await?;

        Ok(row)
    }

    /// Check if this session is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Invalidate this session
    pub async fn invalidate(&mut self, pool: &PgPool) -> cja::Result<()> {
        sqlx::query!(
            r#"
            UPDATE sessions SET is_active = FALSE, updated_at_utc = NOW()
            WHERE id = $1
            "#,
            self.id
        )
        .execute(pool)
        .await
        .wrap_err("Database error invalidating session")?;

        self.is_active = false;
        info!("Session {} invalidated", self.id);

        Ok(())
    }

    /// Get a user for this session
    pub async fn get_user(&self, pool: &PgPool) -> cja::Result<Option<User>> {
        User::get_by_id(pool, self.user_id).await
    }

    /// Update the primary token for this session
    pub async fn set_primary_token(&mut self, pool: &PgPool, token_id: Uuid) -> cja::Result<()> {
        let row = sqlx::query!(
            r#"
            UPDATE sessions SET primary_token_id = $1, updated_at_utc = NOW()
            WHERE id = $2
            RETURNING updated_at_utc
            "#,
            token_id,
            self.id
        )
        .fetch_one(pool)
        .await
        .wrap_err("Database error setting primary token")?;

        self.primary_token_id = Some(token_id);
        self.updated_at_utc = row.updated_at_utc;

        info!(
            "Updated primary token for session {} to {}",
            self.id, token_id
        );

        Ok(())
    }

    // Removed unused method - can be added back when needed

    /// Get the primary token for this session
    pub async fn get_primary_token(
        &self,
        pool: &PgPool,
        app_state: &AppState,
    ) -> cja::Result<Option<crate::oauth::OAuthTokenSet>> {
        let Some(token_id) = self.primary_token_id else {
            return Ok(None);
        };

        // Query the oauth_tokens table to get the token by ID
        let row = sqlx::query!(
            r#"
                SELECT did, access_token, token_type, expires_at, refresh_token, 
                       scope, dpop_jkt, user_id, display_name, handle, id as token_id
                FROM oauth_tokens
                WHERE uuid_id = $1
                "#,
            token_id
        )
        .fetch_optional(pool)
        .await?;

        let row = match row {
            Some(row) => row,
            None => {
                return Ok(None);
            }
        };

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
        }))
    }
}
