use std::{collections::BTreeSet, error::Error, fmt::Display, sync::Arc};

use atrium_api::types::string::Did;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig, DnsTxtResolver},
};
use atrium_oauth::{
    store::{
        session::{MemorySessionStore, Session},
        state::{InternalStateData, MemoryStateStore, StateStore},
    },
    AtprotoClientMetadata, AtprotoLocalhostClientMetadata, DefaultHttpClient, GrantType,
    KnownScope, OAuthClient, OAuthClientConfig, OAuthResolverConfig, Scope,
};
use base64ct::Encoding as _;
use color_eyre::eyre::Context as _;
use elliptic_curve::{JwkEcKey, SecretKey};
use reqwest::redirect;
use sec1::{der::DecodePem as _, pkcs8::DecodePrivateKey as _, EcPrivateKey};
use sqlx::{error, PgPool};

use crate::{
    encryption::decrypt,
    state::{AppState, BlueskyOAuthConfig, DomainSettings, EncryptionConfig},
};

pub struct SomeDnsTxtResolver;

impl DnsTxtResolver for SomeDnsTxtResolver {
    async fn resolve(
        &self,
        domain: &str,
    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync + 'static>> {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
            trust_dns_resolver::config::ResolverConfig::default(),
            trust_dns_resolver::config::ResolverOpts::default(),
        );
        let response = resolver.txt_lookup(domain).await?;
        Ok(response.iter().map(|r| r.to_string()).collect())
    }
}

pub type AtriumOAuthClient = atrium_oauth::OAuthClient<
    DbStateStore,
    DbSessionStore,
    atrium_identity::did::CommonDidResolver<atrium_oauth::DefaultHttpClient>,
    atrium_identity::handle::AtprotoHandleResolver<
        SomeDnsTxtResolver,
        atrium_oauth::DefaultHttpClient,
    >,
>;

pub fn get_private_jwk(bsky_oauth: &BlueskyOAuthConfig) -> cja::Result<elliptic_curve::JwkEcKey> {
    let decoded_private_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bsky_oauth.private_key,
    )
    .wrap_err("Failed to decode base64-encoded private key")?;
    let decoded_private_key = String::from_utf8(decoded_private_key)?;
    println!("decoded_private_key: {}", decoded_private_key);
    let secret_key = SecretKey::<p256::NistP256>::from_sec1_pem(&decoded_private_key)?;
    let jwk = secret_key.to_jwk();

    Ok(jwk)
}

/// Generate a key ID from the key's coordinates
pub fn generate_key_id(x: &[u8], y: &[u8]) -> cja::Result<String> {
    use ring::digest::{Context, SHA256};

    let mut context = Context::new(&SHA256);
    context.update(x);
    context.update(y);
    let digest = context.finish();

    Ok(base64ct::Base64UrlUnpadded::encode_string(digest.as_ref()))
}

fn convert_jwk(from: JwkEcKey) -> cja::Result<jose_jwk::Jwk> {
    let point = from.to_encoded_point::<p256::NistP256>()?;
    let s =
        serde_json::to_string(&from).wrap_err("Failed to serialize elliptic_curve::JwkEcKey")?;
    let mut jwk: jose_jwk::Jwk =
        serde_json::from_str(&s).wrap_err("Failed to deserialize jose_jwk::Jwk")?;
    jwk.prm.alg = Some(jose_jwk::jose_jwa::Algorithm::Signing(
        jose_jwk::jose_jwa::Signing::Es256,
    ));
    jwk.prm.cls = Some(jose_jwk::Class::Signing);
    jwk.prm.ops = Some(BTreeSet::from([jose_jwk::Operations::Sign]));
    jwk.prm.kid = Some(
        generate_key_id(point.x().unwrap(), point.y().unwrap())
            .wrap_err("Failed to generate key ID from elliptic_curve::JwkEcKey")?,
    );
    Ok(jwk)
}

pub struct DbSessionStore {
    db: PgPool,
    encryption: EncryptionConfig,
}

#[derive(thiserror::Error, Debug)]
pub enum DbStoreError {
    #[error(transparent)]
    DbError(#[from] sqlx::Error),
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    EncryptionError(#[from] cja::color_eyre::Report),
}

#[allow(dead_code)]
struct DbAtprotoSession {
    atproto_session_id: uuid::Uuid,
    did: String,
    encrypted_session: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl
    atrium_common::store::Store<
        atrium_api::types::string::Did,
        atrium_oauth::store::session::Session,
    > for DbSessionStore
{
    type Error = DbStoreError;

    async fn get(&self, key: &Did) -> Result<Option<Session>, Self::Error> {
        let session = sqlx::query_as!(
            DbAtprotoSession,
            "SELECT * FROM atproto_sessions WHERE did = $1",
            key.as_str()
        )
        .fetch_optional(&self.db)
        .await?;

        if let Some(s) = session {
            let decrypted = decrypt(&s.encrypted_session, &self.encryption.key).await?;
            let session = serde_json::from_str(&decrypted)?;

            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: Did, value: Session) -> Result<(), Self::Error> {
        let json = serde_json::to_string(&value).unwrap();
        let encrypted = crate::encryption::encrypt(&json, &self.encryption.key).await?;

        sqlx::query!(
            "INSERT INTO atproto_sessions (did, encrypted_session) VALUES ($1, $2)",
            key.as_str(),
            encrypted,
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn del(&self, key: &Did) -> Result<(), Self::Error> {
        sqlx::query!("DELETE FROM atproto_sessions WHERE did = $1", key.as_str())
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        sqlx::query!("TRUNCATE TABLE atproto_sessions")
            .execute(&self.db)
            .await?;

        Ok(())
    }
}

impl atrium_oauth::store::session::SessionStore for DbSessionStore {}

pub fn get_atrium_oauth_client(
    bsky_oauth: &BlueskyOAuthConfig,
    domain: &DomainSettings,
    encryption: &EncryptionConfig,
    db: &PgPool,
) -> cja::Result<AtriumOAuthClient> {
    let http_client = Arc::new(DefaultHttpClient::default());
    let private_jwk = get_private_jwk(bsky_oauth)?;
    dbg!(&private_jwk);
    let jose = convert_jwk(private_jwk)
        .wrap_err("Failed to convert elliptic_curve::JwkEcKey to jose_jwk::Jwk")?;
    dbg!(&jose);
    let config = OAuthClientConfig {
        // TODO: Use the non local host version here
        client_metadata: AtprotoClientMetadata {
            redirect_uris: vec![domain.redirect_uri()],
            scopes: vec![
                Scope::Known(KnownScope::Atproto),
                Scope::Known(KnownScope::TransitionGeneric),
            ],
            client_id: domain.client_id(),
            client_uri: Some(domain.fqdn()),
            token_endpoint_auth_method: atrium_oauth::AuthMethod::PrivateKeyJwt,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            token_endpoint_auth_signing_alg: Some("ES256".to_string()),
            jwks_uri: Some(domain.jwks_uri()),
        },
        keys: Some(vec![jose]),
        resolver: OAuthResolverConfig {
            did_resolver: CommonDidResolver::new(CommonDidResolverConfig {
                plc_directory_url: DEFAULT_PLC_DIRECTORY_URL.to_string(),
                http_client: Arc::clone(&http_client),
            }),
            handle_resolver: AtprotoHandleResolver::new(AtprotoHandleResolverConfig {
                dns_txt_resolver: SomeDnsTxtResolver,
                http_client: Arc::clone(&http_client),
            }),
            authorization_server_metadata: Default::default(),
            protected_resource_metadata: Default::default(),
        },
        state_store: DbStateStore {
            db: db.clone(),
            encryption: encryption.clone(),
        },
        session_store: DbSessionStore {
            db: db.clone(),
            encryption: encryption.clone(),
        },
    };

    // let Ok(client) = OAuthClient::new(config) else {
    //     panic!("failed to create oauth client");
    // };

    let client = OAuthClient::new(config).wrap_err("failed to create oauth client")?;

    Ok(client)
}

pub struct DbStateStore {
    db: PgPool,
    encryption: EncryptionConfig,
}

pub enum DbStateStoreError {}

impl atrium_common::store::Store<String, InternalStateData> for DbStateStore {
    type Error = DbStoreError;

    async fn get(&self, key: &String) -> Result<Option<InternalStateData>, Self::Error> {
        let value = sqlx::query!("SELECT * FROM atproto_states WHERE key = $1", key.as_str())
            .fetch_optional(&self.db)
            .await?;

        if let Some(v) = value {
            let decrypted_state = decrypt(&v.encrypted_state, &self.encryption.key).await?;

            let s = serde_json::from_str(&decrypted_state)?;

            Ok(Some(s))
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: String, value: InternalStateData) -> Result<(), Self::Error> {
        let json = serde_json::to_string(&value).unwrap();
        let encrypted_state = crate::encryption::encrypt(&json, &self.encryption.key).await?;
        sqlx::query!(
            "INSERT INTO atproto_states (key, encrypted_state) VALUES ($1, $2)",
            key.as_str(),
            encrypted_state,
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn del(&self, key: &String) -> Result<(), Self::Error> {
        sqlx::query!("DELETE FROM atproto_states WHERE key = $1", key.as_str())
            .execute(&self.db)
            .await?;

        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        sqlx::query!("TRUNCATE TABLE atproto_states")
            .execute(&self.db)
            .await?;

        Ok(())
    }
}

impl StateStore for DbStateStore {}
