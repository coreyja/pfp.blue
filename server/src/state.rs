use std::env;
use std::sync::Arc;

use age::x25519::Identity;
use atrium_xrpc_client::reqwest::{ReqwestClient, ReqwestClientBuilder};
use color_eyre::eyre::{eyre, WrapErr};
use sea_orm::DatabaseConnection;
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::oauth::new::{AtriumOAuthClient, DbSessionStore, DbStateStore};

#[derive(Clone)]
pub struct BlueskyOAuthConfig {
    pub private_key: String,
    pub public_key: String,
}

impl BlueskyOAuthConfig {
    pub fn from_env() -> cja::Result<Self> {
        let private_key = std::env::var("OAUTH_PRIVATE_KEY")?;
        let public_key = std::env::var("OAUTH_PUBLIC_KEY")?;

        let config = Self {
            private_key,
            public_key,
        };

        config.verify_keys()?;

        Ok(config)
    }

    /// Verify that the keys are properly formatted and can be parsed
    pub fn verify_keys(&self) -> cja::Result<()> {
        use color_eyre::eyre::eyre;
        use std::io::Write;
        use std::process::Command;
        use tempfile::NamedTempFile;

        let decoded_private_key = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.private_key,
        )
        .wrap_err("Failed to decode base64-encoded private key")?;

        let key_preview = if decoded_private_key.len() > 30 {
            format!("{:?}...", &decoded_private_key[..30])
        } else {
            format!("{:?}", decoded_private_key)
        };

        let mut private_temp_file =
            NamedTempFile::new().wrap_err("Failed to create temporary file")?;

        private_temp_file
            .write_all(&decoded_private_key)
            .wrap_err("Failed to write to temporary file")?;

        let private_output = Command::new("openssl")
            .arg("ec")
            .arg("-in")
            .arg(private_temp_file.path())
            .arg("-noout")
            .output()
            .wrap_err("Failed to execute OpenSSL on private key")?;

        if !private_output.status.success() {
            let error = String::from_utf8_lossy(&private_output.stderr);
            return Err(eyre!(
                "OpenSSL verification of private key failed: {}. Key starts with: {}",
                error,
                key_preview
            ));
        }

        let decoded_public_key =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.public_key)
                .wrap_err("Failed to decode base64-encoded public key")?;

        let pub_key_preview = if decoded_public_key.len() > 30 {
            format!("{:?}...", &decoded_public_key[..30])
        } else {
            format!("{:?}", decoded_public_key)
        };

        let mut public_temp_file =
            NamedTempFile::new().wrap_err("Failed to create temporary file for public key")?;

        public_temp_file
            .write_all(&decoded_public_key)
            .wrap_err("Failed to write to temporary file for public key")?;

        let public_output = Command::new("openssl")
            .arg("ec")
            .arg("-pubin")
            .arg("-in")
            .arg(public_temp_file.path())
            .arg("-noout")
            .output()
            .wrap_err("Failed to execute OpenSSL on public key")?;

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

/// This struct holds the age encryption keys used for encrypting sensitive data in the database
#[derive(Clone)]
pub struct EncryptionConfig {
    pub key: Arc<Identity>,
}

impl EncryptionConfig {
    pub fn from_env() -> cja::Result<Self> {
        use color_eyre::eyre::eyre;

        use std::str::FromStr;

        let key_str = std::env::var("ENCRYPTION_KEY")
            .wrap_err("ENCRYPTION_KEY environment variable not set")?;

        let key = Identity::from_str(&key_str)
            .map_err(|e| eyre!("Failed to parse ENCRYPTION_KEY: {}", e))?;

        Ok(Self { key: Arc::new(key) })
    }
}

#[derive(Clone)]
pub struct DomainSettings {
    pub domain: String,
    pub protocol: String,
}

impl DomainSettings {
    /// Returns the OAuth client ID for Bluesky
    pub fn client_id(&self) -> String {
        format!(
            "{}://{}/oauth/bsky/metadata.json",
            self.protocol, self.domain
        )
    }

    pub fn fqdn(&self) -> String {
        format!("{}://{}", self.protocol, self.domain)
    }

    /// Returns the canonical redirect URI for OAuth
    pub fn redirect_uri(&self) -> String {
        format!("{}://{}/oauth/bsky/callback", self.protocol, self.domain)
    }

    pub(crate) fn jwks_uri(&self) -> String {
        format!("{}://{}/oauth/bsky/jwks", self.protocol, self.domain)
    }
}

#[derive(Clone)]
pub struct AtriumState {
    pub oauth: Arc<AtriumOAuthClient>,
    pub sessions: DbSessionStore,
    pub states: DbStateStore,
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::Pool<sqlx::Postgres>,
    pub cookie_key: cja::server::cookies::CookieKey,
    pub domain: DomainSettings,
    pub bsky_client: Arc<ReqwestClient>,
    pub bsky_oauth: BlueskyOAuthConfig,
    pub encryption: EncryptionConfig,
    pub atrium: AtriumState,
    pub orm: DatabaseConnection,
}

impl AppState {
    pub async fn from_env() -> cja::Result<Self> {
        let pool = setup_db_pool().await?;
        let orm_pool: DatabaseConnection = pool.clone().into();

        let cookie_key = cja::server::cookies::CookieKey::from_env_or_generate()?;

        let appview_url =
            env::var("APPVIEW_URL").unwrap_or_else(|_| "https://bsky.social".to_string());
        println!("APPVIEW_URL: {}", appview_url);
        println!("PLC_DIRECTORY_URL: {}", crate::did::get_plc_directory_url());

        let client = ReqwestClientBuilder::new(&appview_url)
            .client(
                reqwest::ClientBuilder::new()
                    .timeout(std::time::Duration::from_millis(1000))
                    .use_rustls_tls()
                    .build()
                    .wrap_err("Failed to build reqwest client")?,
            )
            .build();

        let bsky_oauth = BlueskyOAuthConfig::from_env()?;
        let encryption = EncryptionConfig::from_env()?;

        let domain = DomainSettings {
            domain: std::env::var("DOMAIN")?,
            protocol: std::env::var("PROTO").unwrap_or_else(|_| "https".to_string()),
        };

        let session_store =
            crate::oauth::new::DbSessionStore::new(orm_pool.clone(), encryption.clone());

        let state_store =
            crate::oauth::new::DbStateStore::new(orm_pool.clone(), encryption.clone());

        let atrium_oauth_client = crate::oauth::new::get_atrium_oauth_client(
            &bsky_oauth,
            &domain,
            &encryption,
            &orm_pool,
            &session_store,
            &state_store,
        )?;
        let atrium_oauth_client = Arc::new(atrium_oauth_client);

        let atrium_state = AtriumState {
            oauth: atrium_oauth_client,
            sessions: session_store,
            states: state_store,
        };

        Ok(Self {
            db: pool,
            cookie_key,
            domain,
            bsky_client: Arc::new(client),
            bsky_oauth,
            encryption,
            atrium: atrium_state,
            orm: orm_pool,
        })
    }

    /// Returns the OAuth client ID for Bluesky
    pub fn client_id(&self) -> String {
        self.domain.client_id()
    }

    /// Returns the canonical redirect URI for OAuth
    pub fn redirect_uri(&self) -> String {
        self.domain.redirect_uri()
    }

    /// Returns the configured Avatar CDN URL
    pub fn avatar_cdn_url(&self) -> String {
        env::var("AVATAR_CDN_URL").unwrap_or_else(|_| "https://avatar.bsky.social".to_string())
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

    let database_url = std::env::var("DATABASE_URL").wrap_err("DATABASE_URL must be set")?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    sqlx::query!("SELECT pg_advisory_lock($1)", MIGRATION_LOCK_ID)
        .execute(&pool)
        .await?;

    sqlx::migrate!("../migrations").run(&pool).await?;

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
        None => return Err(eyre!("Failed to unlock migration lock")),
    }

    Ok(pool)
}
