use std::sync::Arc;

use atrium_xrpc_client::reqwest::{ReqwestClient, ReqwestClientBuilder};
use sqlx::{postgres::PgPoolOptions, PgPool};

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::Pool<sqlx::Postgres>,
    pub cookie_key: cja::server::cookies::CookieKey,
    pub domain: String,
    pub bsky_client: Arc<ReqwestClient>,
}

impl AppState {
    pub async fn from_env() -> cja::Result<Self> {
        let pool = setup_db_pool().await?;

        let cookie_key = cja::server::cookies::CookieKey::from_env_or_generate()?;

        let client = ReqwestClientBuilder::new("https://bsky.social")
            .client(
                reqwest::ClientBuilder::new()
                    .timeout(std::time::Duration::from_millis(1000))
                    .use_rustls_tls()
                    .build()
                    .unwrap(),
            )
            .build();

        Ok(Self {
            db: pool,
            cookie_key,
            domain: std::env::var("DOMAIN")?,
            bsky_client: Arc::new(client),
        })
    }
}

impl cja::app_state::AppState for AppState {
    fn version(&self) -> &str {
        env!("VERGEN_GIT_SHA")
    }

    fn db(&self) -> &sqlx::PgPool {
        &self.db
    }

    fn cookie_key(&self) -> &cja::server::cookies::CookieKey {
        &self.cookie_key
    }
}

#[tracing::instrument(err)]
pub async fn setup_db_pool() -> cja::Result<PgPool> {
    const MIGRATION_LOCK_ID: i64 = 0xDB_DB_DB_DB_DB_DB_DB;

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    sqlx::query!("SELECT pg_advisory_lock($1)", MIGRATION_LOCK_ID)
        .execute(&pool)
        .await?;

    sqlx::migrate!().run(&pool).await?;

    let unlock_result = sqlx::query!("SELECT pg_advisory_unlock($1)", MIGRATION_LOCK_ID)
        .fetch_one(&pool)
        .await?
        .pg_advisory_unlock;

    match unlock_result {
        Some(b) => {
            if b {
                tracing::info!("Migration lock unlocked");
            } else {
                tracing::info!("Failed to unlock migration lock");
            }
        }
        None => panic!("Failed to unlock migration lock"),
    }

    Ok(pool)
}
