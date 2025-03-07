use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Represents a profile picture progress setting in the database
#[derive(Debug, Clone)]
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
        .await?;

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
        .await?;

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
        sqlx::query!(
            r#"
            UPDATE profile_picture_progress
            SET enabled = $1, updated_at_utc = NOW()
            WHERE id = $2
            "#,
            enabled,
            self.id
        )
        .execute(pool)
        .await?;

        self.enabled = enabled;
        Ok(())
    }

    /// Update the original blob CID
    pub async fn update_original_blob_cid(
        &mut self,
        pool: &PgPool,
        original_blob_cid: Option<String>,
    ) -> cja::Result<()> {
        sqlx::query!(
            r#"
            UPDATE profile_picture_progress
            SET original_blob_cid = $1, updated_at_utc = NOW()
            WHERE id = $2
            "#,
            original_blob_cid.as_ref(),
            self.id
        )
        .execute(pool)
        .await?;

        self.original_blob_cid = original_blob_cid;
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
            return Ok(settings);
        }

        // Create new settings if none exist
        Self::create(pool, token_id, default_enabled, default_original_blob_cid).await
    }

    /// Get all enabled profile picture progress settings
    pub async fn get_all_enabled(pool: &PgPool) -> cja::Result<Vec<Self>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, token_id, enabled, original_blob_cid, created_at_utc, updated_at_utc
            FROM profile_picture_progress
            WHERE enabled = TRUE
            "#
        )
        .fetch_all(pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Self {
                id: r.id,
                token_id: r.token_id,
                enabled: r.enabled,
                original_blob_cid: r.original_blob_cid,
                created_at_utc: r.created_at_utc,
                updated_at_utc: r.updated_at_utc,
            })
            .collect())
    }
}
