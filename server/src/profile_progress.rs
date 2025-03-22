use chrono::{DateTime, Utc};
use color_eyre::eyre::eyre;
use sqlx::PgPool;
use tracing::{error, info};
use uuid::Uuid;

/// Represents a profile picture progress setting in the database
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields needed for database operations
pub struct ProfilePictureProgress {
    /// Unique ID for this progress setting
    pub id: Uuid,
    /// ID of the OAuth token this setting belongs to
    pub token_id: Uuid,
    /// Whether the feature is enabled
    pub enabled: bool,
    /// CID of the original profile picture blob
    pub original_blob_cid: Option<String>,
    /// When this record was created
    pub created_at_utc: DateTime<Utc>,
    /// When this record was last updated
    pub updated_at_utc: DateTime<Utc>,
}

impl ProfilePictureProgress {
    /// Create a new profile picture progress setting
    pub async fn create(
        pool: &PgPool,
        token_id: Uuid,
        enabled: bool,
        original_blob_cid: Option<String>,
    ) -> cja::Result<Self> {
        let row = sqlx::query!(
            r#"
            INSERT INTO profile_picture_progress (token_id, enabled, original_blob_cid)
            VALUES ($1, $2, $3)
            RETURNING id, token_id, enabled, original_blob_cid, created_at_utc, updated_at_utc
            "#,
            token_id,
            enabled,
            original_blob_cid
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!("Failed to create profile picture progress: {:?}", e);
            eyre!("Database error creating profile picture progress: {}", e)
        })?;

        info!(
            "Created profile picture progress setting for token {}",
            token_id
        );

        Ok(Self {
            id: row.id,
            token_id: row.token_id,
            enabled: row.enabled,
            original_blob_cid: row.original_blob_cid,
            created_at_utc: row.created_at_utc,
            updated_at_utc: row.updated_at_utc,
        })
    }

    /// Get a profile picture progress setting by token ID
    pub async fn get_by_token_id(pool: &PgPool, token_id: Uuid) -> cja::Result<Option<Self>> {
        let row = sqlx::query!(
            r#"
            SELECT id, token_id, enabled, original_blob_cid, created_at_utc, updated_at_utc 
            FROM profile_picture_progress
            WHERE token_id = $1
            "#,
            token_id
        )
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            error!("Failed to query profile picture progress: {:?}", e);
            eyre!("Database error querying profile picture progress: {}", e)
        })?;

        Ok(row.map(|r| Self {
            id: r.id,
            token_id: r.token_id,
            enabled: r.enabled,
            original_blob_cid: r.original_blob_cid,
            created_at_utc: r.created_at_utc,
            updated_at_utc: r.updated_at_utc,
        }))
    }

    /// Update the enabled status
    pub async fn update_enabled(&mut self, pool: &PgPool, enabled: bool) -> cja::Result<()> {
        let row = sqlx::query!(
            r#"
            UPDATE profile_picture_progress
            SET enabled = $1, updated_at_utc = NOW()
            WHERE id = $2
            RETURNING updated_at_utc
            "#,
            enabled,
            self.id
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!(
                "Failed to update profile picture progress enabled status: {:?}",
                e
            );
            eyre!("Database error updating profile picture progress: {}", e)
        })?;

        self.enabled = enabled;
        self.updated_at_utc = row.updated_at_utc;

        info!(
            "Updated profile picture progress enabled status to {} for ID {}",
            enabled, self.id
        );

        Ok(())
    }

    // This method is kept for backwards compatibility but should be considered deprecated
    // We now store profile pictures in the PDS instead of our database
    #[allow(dead_code)]
    async fn update_original_blob_cid(
        &mut self,
        pool: &PgPool,
        original_blob_cid: Option<String>,
    ) -> cja::Result<()> {
        let row = sqlx::query!(
            r#"
            UPDATE profile_picture_progress
            SET original_blob_cid = $1, updated_at_utc = NOW()
            WHERE id = $2
            RETURNING updated_at_utc
            "#,
            original_blob_cid.as_ref(),
            self.id
        )
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!(
                "Failed to update profile picture original blob CID: {:?}",
                e
            );
            eyre!("Database error updating profile picture blob CID: {}", e)
        })?;

        self.original_blob_cid = original_blob_cid.clone();
        self.updated_at_utc = row.updated_at_utc;

        info!(
            "Updated profile picture original blob CID to {:?} for ID {}",
            original_blob_cid, self.id
        );

        Ok(())
    }

    /// Get or create a profile picture progress setting
    pub async fn get_or_create(
        pool: &PgPool,
        token_id: Uuid,
        default_enabled: bool,
        default_original_blob_cid: Option<String>,
    ) -> cja::Result<Self> {
        // Try to get existing settings
        if let Some(settings) = Self::get_by_token_id(pool, token_id).await? {
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
        Self::create(pool, token_id, default_enabled, default_original_blob_cid).await
    }

    // Removed these methods as they're not used in the current implementation
    // We can add them back when needed
}
