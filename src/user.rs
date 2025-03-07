use chrono::{DateTime, Utc};
use sqlx::{postgres::PgPool, Row};
use uuid::Uuid;

/// Represents a user in the system
#[derive(Debug, Clone)]
pub struct User {
    /// Unique user ID
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
            SELECT * FROM users WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            user_id: r.get("user_id"),
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
            user_id: row.get("user_id"),
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
            JOIN oauth_tokens ot ON u.user_id = ot.user_id
            WHERE ot.did = $1 AND ot.is_active = TRUE
            LIMIT 1
            "#,
        )
        .bind(did)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| User {
            user_id: r.get("user_id"),
            username: r.get("username"),
            email: r.get("email"),
            created_at_utc: r.get("created_at_utc"),
            updated_at_utc: r.get("updated_at_utc"),
        }))
    }

    /// Get all DIDs (from OAuth tokens) associated with this user
    pub async fn get_dids(&self, pool: &PgPool) -> cja::Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT did FROM oauth_tokens
            WHERE user_id = $1 AND is_active = TRUE
            "#,
        )
        .bind(self.user_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.get("did")).collect())
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
    ) -> cja::Result<Session> {
        // Calculate expiration time
        let expires_at = Utc::now() + chrono::Duration::days(duration_days);

        let row = sqlx::query(
            r#"
            INSERT INTO sessions (user_id, expires_at, user_agent, ip_address)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(expires_at)
        .bind(user_agent)
        .bind(ip_address)
        .fetch_one(pool)
        .await?;

        Ok(Session {
            session_id: row.get("session_id"),
            user_id: row.get("user_id"),
            expires_at: row.get("expires_at"),
            user_agent: row.get("user_agent"),
            ip_address: row.get("ip_address"),
            is_active: row.get("is_active"),
            created_at_utc: row.get("created_at_utc"),
            updated_at_utc: row.get("updated_at_utc"),
        })
    }

    /// Get a session by its ID
    pub async fn get_by_id(pool: &PgPool, session_id: Uuid) -> cja::Result<Option<Session>> {
        let row = sqlx::query(
            r#"
            SELECT * FROM sessions WHERE session_id = $1
            "#,
        )
        .bind(session_id)
        .fetch_optional(pool)
        .await?;

        Ok(row.map(|r| Session {
            session_id: r.get("session_id"),
            user_id: r.get("user_id"),
            expires_at: r.get("expires_at"),
            user_agent: r.get("user_agent"),
            ip_address: r.get("ip_address"),
            is_active: r.get("is_active"),
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
            WHERE session_id = $1
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
}
