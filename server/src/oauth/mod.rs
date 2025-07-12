//! OAuth module for handling BlueskyOAuth operations
//! This includes working with JWKs, DPoP proofs, and OAuth sessions

// Re-export submodules
pub mod db;
pub mod jwk;

// Re-export main types and functions
pub use jwk::*;

use std::{collections::BTreeSet, sync::Arc};

use atrium_api::types::string::Did;
use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig},
    handle::{AppViewHandleResolver, AppViewHandleResolverConfig},
};
use atrium_oauth::{
    store::{
        session::Session,
        state::{InternalStateData, StateStore},
    },
    AtprotoClientMetadata, GrantType, KnownScope, OAuthClient, OAuthClientConfig,
    OAuthResolverConfig, Scope,
};
use base64ct::Encoding as _;
use color_eyre::eyre::Context as _;
use elliptic_curve::{JwkEcKey, SecretKey};
use sea_orm::{
    ActiveValue, ColumnTrait as _, DatabaseConnection, EntityTrait as _, QueryFilter as _,
};

use crate::{
    encryption::decrypt,
    http::MyHttpClient,
    state::{BlueskyOAuthConfig, DomainSettings, EncryptionConfig},
};

use crate::orm::prelude::*;

pub type AtriumOAuthClient = atrium_oauth::OAuthClient<
    DbStateStore,
    DbSessionStore,
    atrium_identity::did::CommonDidResolver<MyHttpClient>,
    atrium_identity::handle::AppViewHandleResolver<MyHttpClient>,
    MyHttpClient,
>;

pub fn get_private_jwk(bsky_oauth: &BlueskyOAuthConfig) -> cja::Result<elliptic_curve::JwkEcKey> {
    let decoded_private_key = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bsky_oauth.private_key,
    )
    .wrap_err("Failed to decode base64-encoded private key")?;
    let decoded_private_key = String::from_utf8(decoded_private_key)?;
    println!("decoded_private_key: {decoded_private_key}");
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
        generate_key_id(
            point
                .x()
                .ok_or_else(|| cja::color_eyre::eyre::eyre!("Failed to get x coordinate"))?,
            point
                .y()
                .ok_or_else(|| cja::color_eyre::eyre::eyre!("Failed to get y coordinate"))?,
        )
        .wrap_err("Failed to generate key ID from elliptic_curve::JwkEcKey")?,
    );
    Ok(jwk)
}

#[derive(Clone)]
pub struct DbSessionStore {
    orm: DatabaseConnection,
    encryption: EncryptionConfig,
}

impl DbSessionStore {
    pub fn new(orm: DatabaseConnection, encryption: EncryptionConfig) -> Self {
        Self { orm, encryption }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DbStoreError {
    #[error(transparent)]
    Db(#[from] sea_orm::DbErr),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Encryption(#[from] cja::color_eyre::Report),
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
        let session = AtprotoSessions::find()
            .filter(crate::orm::atproto_sessions::Column::Did.eq(key.as_str()))
            .one(&self.orm)
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
        let json = serde_json::to_string(&value)?;
        let encrypted = crate::encryption::encrypt(&json, &self.encryption.key).await?;

        let active_model = crate::orm::atproto_sessions::ActiveModel {
            did: ActiveValue::set(key.to_string()),
            encrypted_session: ActiveValue::set(encrypted),
            ..Default::default()
        };

        crate::orm::atproto_sessions::Entity::insert(active_model)
            .on_conflict(
                sea_query::OnConflict::column(crate::orm::atproto_sessions::Column::Did)
                    .update_column(crate::orm::atproto_sessions::Column::EncryptedSession)
                    .to_owned(),
            )
            .exec(&self.orm)
            .await?;

        Ok(())
    }

    async fn del(&self, key: &Did) -> Result<(), Self::Error> {
        crate::orm::atproto_sessions::Entity::delete_many()
            .filter(crate::orm::atproto_sessions::Column::Did.eq(key.as_str()))
            .exec(&self.orm)
            .await?;

        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        crate::orm::atproto_sessions::Entity::delete_many()
            .exec(&self.orm)
            .await?;

        Ok(())
    }
}

impl atrium_oauth::store::session::SessionStore for DbSessionStore {}

pub fn get_atrium_oauth_client(
    bsky_oauth: &BlueskyOAuthConfig,
    domain: &DomainSettings,
    session_store: &DbSessionStore,
    state_store: &DbStateStore,
) -> cja::Result<AtriumOAuthClient> {
    let http_client = MyHttpClient::default();
    let arced_http_client = Arc::new(http_client.clone());
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
                plc_directory_url: crate::did::get_plc_directory_url(),
                http_client: arced_http_client.clone(),
            }),
            handle_resolver: AppViewHandleResolver::new(AppViewHandleResolverConfig {
                service_url: std::env::var("APPVIEW_URL")
                    .unwrap_or_else(|_| "https://bsky.social".to_string()),
                http_client: arced_http_client.clone(),
            }),
            authorization_server_metadata: Default::default(),
            protected_resource_metadata: Default::default(),
        },
        state_store: state_store.clone(),
        session_store: session_store.clone(),
        http_client,
    };

    let client = OAuthClient::new(config).wrap_err("failed to create oauth client")?;

    Ok(client)
}

#[derive(Clone)]
pub struct DbStateStore {
    orm: DatabaseConnection,
    encryption: EncryptionConfig,
}

impl DbStateStore {
    pub fn new(orm: DatabaseConnection, encryption: EncryptionConfig) -> Self {
        Self { orm, encryption }
    }
}

impl atrium_common::store::Store<String, InternalStateData> for DbStateStore {
    type Error = DbStoreError;

    async fn get(&self, key: &String) -> Result<Option<InternalStateData>, Self::Error> {
        let state = AtprotoStates::find()
            .filter(crate::orm::atproto_states::Column::Key.eq(key.as_str()))
            .one(&self.orm)
            .await?;

        if let Some(s) = state {
            let decrypted = decrypt(&s.encrypted_state, &self.encryption.key).await?;
            let state = serde_json::from_str(&decrypted)?;

            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    async fn set(&self, key: String, value: InternalStateData) -> Result<(), Self::Error> {
        let json = serde_json::to_string(&value)?;
        let encrypted_state = crate::encryption::encrypt(&json, &self.encryption.key).await?;
        let active_model = crate::orm::atproto_states::ActiveModel {
            key: ActiveValue::set(key.to_string()),
            encrypted_state: ActiveValue::set(encrypted_state),
            ..Default::default()
        };

        crate::orm::atproto_states::Entity::insert(active_model)
            .on_conflict(
                sea_query::OnConflict::column(crate::orm::atproto_states::Column::Key)
                    .update_column(crate::orm::atproto_states::Column::EncryptedState)
                    .to_owned(),
            )
            .exec(&self.orm)
            .await?;

        Ok(())
    }

    async fn del(&self, key: &String) -> Result<(), Self::Error> {
        crate::orm::atproto_states::Entity::delete_many()
            .filter(crate::orm::atproto_states::Column::Key.eq(key.as_str()))
            .exec(&self.orm)
            .await?;

        Ok(())
    }

    async fn clear(&self) -> Result<(), Self::Error> {
        crate::orm::atproto_states::Entity::delete_many()
            .exec(&self.orm)
            .await?;

        Ok(())
    }
}

impl StateStore for DbStateStore {}
