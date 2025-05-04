use chrono::{DateTime, Utc};
use color_eyre::eyre::Context;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

/// Represents a profile picture progress setting in the database
#[derive(Debug, Clone)]
#[allow(dead_code)]
// Fields needed for database operations
pub struct ProfilePictureProgress {
    /// Unique ID for this progress setting
    pub id: Uuid,
    /// ID of the OAuth token this setting belongs to
    pub account_id: Uuid,
    /// Whether the feature is enabled
    pub enabled: bool,
    /// When this record was created
    pub created_at_utc: DateTime<Utc>,
    /// When this record was last updated
    pub updated_at_utc: DateTime<Utc>,
}

impl ProfilePictureProgress {
    /// Create a new profile picture progress setting
    pub async fn create(pool: &PgPool, account_id: Uuid, enabled: bool) -> cja::Result<Self> {
        let row = sqlx::query!(
            r#"
            INSERT INTO profile_picture_progress (account_id, enabled)
            VALUES ($1, $2)
            RETURNING profile_picture_progress_id, account_id, enabled, created_at, updated_at
            "#,
            account_id,
            enabled,
        )
        .fetch_one(pool)
        .await
        .wrap_err("Database error creating profile picture progress")?;

        info!(
            "Created profile picture progress setting for token {}",
            account_id
        );

        Ok(Self {
            id: row.profile_picture_progress_id,
            account_id: row.account_id,
            enabled: row.enabled,
            created_at_utc: row.created_at,
            updated_at_utc: row.updated_at,
        })
    }

    /// Get a profile picture progress setting by token ID
    pub async fn get_by_account_id(pool: &PgPool, account_id: Uuid) -> cja::Result<Option<Self>> {
        let row = sqlx::query_as!(
            Self,
            r#"
            SELECT profile_picture_progress_id as id, account_id, enabled, created_at as created_at_utc, updated_at as updated_at_utc 
            FROM profile_picture_progress
            WHERE account_id = $1
            "#,
            account_id
        )
        .fetch_optional(pool)
        .await
        .wrap_err("Database error querying profile picture progress")?;

        Ok(row)
    }

    /// Update the enabled status
    pub async fn update_enabled(&mut self, pool: &PgPool, enabled: bool) -> cja::Result<()> {
        let row = sqlx::query!(
            r#"
            UPDATE profile_picture_progress
            SET enabled = $1, updated_at = NOW()
            WHERE profile_picture_progress_id = $2
            RETURNING updated_at
            "#,
            enabled,
            self.id
        )
        .fetch_one(pool)
        .await
        .wrap_err("Database error updating profile picture progress")?;

        self.enabled = enabled;
        self.updated_at_utc = row.updated_at;

        info!(
            "Updated profile picture progress enabled status to {} for ID {}",
            enabled, self.id
        );

        Ok(())
    }

    /// Get or create a profile picture progress setting
    pub async fn get_or_create(
        pool: &PgPool,
        token_id: Uuid,
        default_enabled: bool,
    ) -> cja::Result<Self> {
        // Try to get existing settings
        if let Some(settings) = Self::get_by_account_id(pool, token_id).await? {
            info!(
                "Found existing profile picture progress settings for token {}",
                token_id
            );
            return Ok(settings);
        }

        // Create new settings if none exist
        info!(
            "Creating new profile picture progress settings for token {}",
            token_id
        );
        Self::create(pool, token_id, default_enabled).await
    }
}
