use std::sync::Arc;

use atrium_xrpc_client::reqwest::{ReqwestClient, ReqwestClientBuilder};
use sqlx::{postgres::PgPoolOptions, PgPool};

#[derive(Clone)]
pub struct BlueskyOAuthConfig {
    pub private_key: String,
    pub public_key: String,
    // Kept for compatibility with environment variables but not used
    #[deprecated(note = "not used")]
    pub client_secret: String,
}

impl BlueskyOAuthConfig {
    pub fn from_env() -> cja::Result<Self> {
        let private_key = std::env::var("OAUTH_PRIVATE_KEY")?;
        let public_key = std::env::var("OAUTH_PUBLIC_KEY")?;
        let client_secret = std::env::var("OAUTH_CLIENT_SECRET")?;

        let config = Self {
            private_key,
            public_key,
            client_secret,
        };

        // Verify keys at startup
        config.verify_keys()?;

        Ok(config)
    }

    /// Verify that the keys are properly formatted and can be parsed
    pub fn verify_keys(&self) -> cja::Result<()> {
        use color_eyre::eyre::eyre;
        use std::io::Write;
        use std::process::Command;
        use tempfile::NamedTempFile;

        // Decode base64-encoded private key
        let decoded_private_key = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.private_key,
        ) {
            Ok(key) => key,
            Err(e) => return Err(eyre!("Failed to decode base64-encoded private key: {}", e)),
        };

        let key_preview = if decoded_private_key.len() > 30 {
            format!("{:?}...", &decoded_private_key[..30])
        } else {
            format!("{:?}", decoded_private_key)
        };

        // Write to temp file and verify with OpenSSL directly
        let mut private_temp_file =
            NamedTempFile::new().map_err(|e| eyre!("Failed to create temporary file: {}", e))?;

        private_temp_file
            .write_all(&decoded_private_key)
            .map_err(|e| eyre!("Failed to write to temporary file: {}", e))?;

        // Try to verify the key with OpenSSL
        let private_output = Command::new("openssl")
            .arg("ec")
            .arg("-in")
            .arg(private_temp_file.path())
            .arg("-noout")
            .output()
            .map_err(|e| eyre!("Failed to execute OpenSSL on private key: {}", e))?;

        if !private_output.status.success() {
            let error = String::from_utf8_lossy(&private_output.stderr);
            return Err(eyre!(
                "OpenSSL verification of private key failed: {}. Key starts with: {}",
                error,
                key_preview
            ));
        }

        // Decode base64-encoded public key
        let decoded_public_key = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.public_key,
        ) {
            Ok(key) => key,
            Err(e) => return Err(eyre!("Failed to decode base64-encoded public key: {}", e)),
        };

        let pub_key_preview = if decoded_public_key.len() > 30 {
            format!("{:?}...", &decoded_public_key[..30])
        } else {
            format!("{:?}", decoded_public_key)
        };

        // Write to temp file and verify with OpenSSL directly
        let mut public_temp_file = NamedTempFile::new()
            .map_err(|e| eyre!("Failed to create temporary file for public key: {}", e))?;

        public_temp_file
            .write_all(&decoded_public_key)
            .map_err(|e| eyre!("Failed to write to temporary file for public key: {}", e))?;

        // Try to verify the public key with OpenSSL
        let public_output = Command::new("openssl")
            .arg("ec")
            .arg("-pubin")
            .arg("-in")
            .arg(public_temp_file.path())
            .arg("-noout")
            .output()
            .map_err(|e| eyre!("Failed to execute OpenSSL on public key: {}", e))?;

        if !public_output.status.success() {
            let error = String::from_utf8_lossy(&public_output.stderr);
            return Err(eyre!(
                "OpenSSL verification of public key failed: {}. Key starts with: {}",
                error,
                pub_key_preview
            ));
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::Pool<sqlx::Postgres>,
    pub cookie_key: cja::server::cookies::CookieKey,
    pub domain: String,
    pub protocol: String,
    pub bsky_client: Arc<ReqwestClient>,
    pub bsky_oauth: BlueskyOAuthConfig,
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

        let bsky_oauth = BlueskyOAuthConfig::from_env()?;

        Ok(Self {
            db: pool,
            cookie_key,
            domain: std::env::var("DOMAIN")?,
            protocol: std::env::var("PROTO").unwrap_or_else(|_| "https".to_string()),
            bsky_client: Arc::new(client),
            bsky_oauth,
        })
    }

    /// Returns the OAuth client ID for Bluesky
    /// This should return a consistent value regardless of local development or production
    pub fn client_id(&self) -> String {
        // For OAuth, we need to use a consistent client ID
        // During local dev, we'll use the production domain for the client ID
        // but still use localhost for the actual callbacks

        // If we're running on localhost, use prod domain for client ID
        if self.domain.contains("localhost") || self.domain.contains("127.0.0.1") {
            "https://pfp.blue/oauth/bsky/metadata.json".to_string()
        } else {
            // Otherwise use the actual domain
            format!(
                "{}://{}/oauth/bsky/metadata.json",
                self.protocol, self.domain
            )
        }
    }

    /// Returns the canonical redirect URI for OAuth
    pub fn redirect_uri(&self) -> String {
        format!("{}://{}/oauth/bsky/callback", self.protocol, self.domain)
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
