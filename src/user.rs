use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPool, Row};
use uuid::Uuid;

/// Represents a user in the system
#[derive(Debug, Clone)]
pub struct User {
    /// Unique user ID (matches database column 'id')
    pub user_id: Uuid,
    /// Optional username
    pub username: Option<String>,
    /// Optional email
    pub email: Option<String>,
    /// When the user was created
    pub created_at_utc: DateTime<Utc>,
    /// When the user was last updated
    pub updated_at_utc: DateTime<Utc>,
}

/// Represents a session for authenticated users
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session ID (used in cookies)
    pub session_id: Uuid,
    /// The user this session belongs to
    pub user_id: Uuid,
    /// When this session expires
    pub expires_at: DateTime<Utc>,
    /// Optional user agent
    pub user_agent: Option<String>,
    /// Optional IP address
    pub ip_address: Option<String>,
    /// Whether this session is active
    pub is_active: bool,
    /// ID of the primary OAuth token for this session (if set)
    pub primary_token_id: Option<Uuid>,
    /// When the session was created
    pub created_at_utc: DateTime<Utc>,
    /// When the session was last updated
    pub updated_at_utc: DateTime<Utc>,
}

impl User {
    /// Get a user by their ID
    pub async fn get_by_id(pool: &PgPool, user_id: Uuid) -> cja::Result<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT * FROM users WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            user_id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            created_at_utc: r.get("created_at_utc"),
            updated_at_utc: r.get("updated_at_utc"),
        }))
    }

    /// Create a new user with optional username and email
    pub async fn create(
        pool: &PgPool,
        username: Option<String>,
        email: Option<String>,
    ) -> cja::Result<User> {
        let row = sqlx::query(
            r#"
            INSERT INTO users (username, email)
            VALUES ($1, $2)
            RETURNING *
            "#,
        )
        .bind(username)
        .bind(email)
        .fetch_one(pool)
        .await?;

        Ok(User {
            user_id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            created_at_utc: row.get("created_at_utc"),
            updated_at_utc: row.get("updated_at_utc"),
        })
    }

    /// Get a user by the DID of one of their OAuth tokens
    pub async fn get_by_did(pool: &PgPool, did: &str) -> cja::Result<Option<User>> {
        let row = sqlx::query(
            r#"
            SELECT u.* FROM users u
            JOIN oauth_tokens ot ON u.id = ot.user_id
            WHERE ot.did = $1
            LIMIT 1
            "#,
        )
        .bind(did)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            user_id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            created_at_utc: r.get("created_at_utc"),
            updated_at_utc: r.get("updated_at_utc"),
        }))
    }
}

impl Session {
    /// Create a new session for a user
    pub async fn create(
        pool: &PgPool,
        user_id: Uuid,
        user_agent: Option<String>,
        ip_address: Option<String>,
        duration_days: i64,
        primary_token_id: Option<Uuid>,
    ) -> cja::Result<Session> {
        // Calculate expiration time
        let expires_at = Utc::now() + chrono::Duration::days(duration_days);

        let row = sqlx::query(
            r#"
            INSERT INTO sessions (user_id, expires_at, user_agent, ip_address, primary_token_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(expires_at)
        .bind(user_agent)
        .bind(ip_address)
        .bind(primary_token_id)
        .fetch_one(pool)
        .await?;

        Ok(Session {
            session_id: row.get("id"),
            user_id: row.get("user_id"),
            expires_at: row.get("expires_at"),
            user_agent: row.get("user_agent"),
            ip_address: row.get("ip_address"),
            is_active: row.get("is_active"),
            primary_token_id: row.get("primary_token_id"),
            created_at_utc: row.get("created_at_utc"),
            updated_at_utc: row.get("updated_at_utc"),
        })
    }

    /// Get a session by its ID
    pub async fn get_by_id(pool: &PgPool, session_id: Uuid) -> cja::Result<Option<Session>> {
        let row = sqlx::query(
            r#"
            SELECT * FROM sessions WHERE id = $1
            "#,
        )
        .bind(session_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| Session {
            session_id: r.get("id"),
            user_id: r.get("user_id"),
            expires_at: r.get("expires_at"),
            user_agent: r.get("user_agent"),
            ip_address: r.get("ip_address"),
            is_active: r.get("is_active"),
            primary_token_id: r.get("primary_token_id"),
            created_at_utc: r.get("created_at_utc"),
            updated_at_utc: r.get("updated_at_utc"),
        }))
    }

    /// Check if this session is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Invalidate this session
    pub async fn invalidate(&mut self, pool: &PgPool) -> cja::Result<()> {
        sqlx::query(
            r#"
            UPDATE sessions SET is_active = FALSE
            WHERE id = $1
            "#,
        )
        .bind(self.session_id)
        .execute(pool)
        .await?;

        self.is_active = false;
        Ok(())
    }

    /// Get a user for this session
    pub async fn get_user(&self, pool: &PgPool) -> cja::Result<Option<User>> {
        User::get_by_id(pool, self.user_id).await
    }

    /// Update the primary token for this session
    pub async fn set_primary_token(&mut self, pool: &PgPool, token_id: Uuid) -> cja::Result<()> {
        sqlx::query(
            r#"
            UPDATE sessions SET primary_token_id = $1, updated_at_utc = NOW()
            WHERE id = $2
            "#,
        )
        .bind(token_id)
        .bind(self.session_id)
        .execute(pool)
        .await?;

        self.primary_token_id = Some(token_id);
        Ok(())
    }

    /// Clear the primary token for this session
    pub async fn clear_primary_token(&mut self, pool: &PgPool) -> cja::Result<()> {
        sqlx::query(
            r#"
            UPDATE sessions SET primary_token_id = NULL, updated_at_utc = NOW()
            WHERE id = $1
            "#,
        )
        .bind(self.session_id)
        .execute(pool)
        .await?;

        self.primary_token_id = None;
        Ok(())
    }

    /// Get the primary token for this session
    pub async fn get_primary_token(
        &self,
        pool: &PgPool,
    ) -> cja::Result<Option<crate::oauth::OAuthTokenSet>> {
        if let Some(token_id) = self.primary_token_id {
            // Query the oauth_tokens table to get the token by ID
            let row = sqlx::query(
                r#"
                SELECT uuid_id, did, access_token, token_type, expires_at, refresh_token, scope, dpop_jkt, user_id, handle
                FROM oauth_tokens
                WHERE uuid_id = $1
                "#,
            )
            .bind(token_id)
            .fetch_optional(pool)
            .await?;

            if let Some(row) = row {
                // Convert the row to an OAuthTokenSet
                return Ok(Some(crate::oauth::OAuthTokenSet {
                    did: row.get("did"),
                    access_token: row.get("access_token"),
                    token_type: row.get("token_type"),
                    expires_at: row.get::<i64, _>("expires_at") as u64,
                    refresh_token: row.get("refresh_token"),
                    scope: row.get("scope"),
                    handle: row.get("handle"),
                    dpop_jkt: row.get("dpop_jkt"),
                    user_id: row.get("user_id"),
                }));
            }
        }

        // If no primary token is set or it's not found, return None
        Ok(None)
    }
}