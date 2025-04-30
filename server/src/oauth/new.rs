use std::{collections::BTreeSet, error::Error, sync::Arc};

use atrium_identity::{
    did::{CommonDidResolver, CommonDidResolverConfig, DEFAULT_PLC_DIRECTORY_URL},
    handle::{AtprotoHandleResolver, AtprotoHandleResolverConfig, DnsTxtResolver},
};
use atrium_oauth::{
    store::{session::MemorySessionStore, state::MemoryStateStore},
    AtprotoClientMetadata, AtprotoLocalhostClientMetadata, DefaultHttpClient, GrantType,
    KnownScope, OAuthClient, OAuthClientConfig, OAuthResolverConfig, Scope,
};
use base64ct::Encoding as _;
use color_eyre::eyre::Context as _;
use elliptic_curve::{JwkEcKey, SecretKey};
use reqwest::redirect;
use sec1::{der::DecodePem as _, pkcs8::DecodePrivateKey as _, EcPrivateKey};

use crate::state::{AppState, BlueskyOAuthConfig, DomainSettings};

pub struct SomeDnsTxtResolver;

impl DnsTxtResolver for SomeDnsTxtResolver {
    async fn resolve(
        &self,
        _: &str,
    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync + 'static>> {
        todo!()
    }
}

pub type AtriumOAuthClient = atrium_oauth::OAuthClient<
    atrium_common::store::memory::MemoryStore<
        std::string::String,
        atrium_oauth::store::state::InternalStateData,
    >,
    atrium_common::store::memory::MemoryStore<
        atrium_api::types::string::Did,
        atrium_oauth::store::session::Session,
    >,
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
fn generate_key_id(x: &[u8], y: &[u8]) -> cja::Result<String> {
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

pub fn get_atrium_oauth_client(
    bsky_oauth: &BlueskyOAuthConfig,
    domain: &DomainSettings,
) -> cja::Result<AtriumOAuthClient> {
    let http_client = Arc::new(DefaultHttpClient::default());
    // // Generate JWK for the client metadata
    // // let base64_decoded = base64::decode(&bsky_oauth.private_key)?;
    // let decoded_private_key = base64::Engine::decode(
    //     &base64::engine::general_purpose::STANDARD,
    //     &bsky_oauth.private_key,
    // )
    // .wrap_err("Failed to decode base64-encoded private key")?;
    // // let decoded_private_key = String::from_utf8(decoded_private_key)?;
    // // dbg!(&decoded_private_key);
    // let private_jwk = jose_jwk::Jwk::from_ec_pem(&decoded_private_key);
    let private_jwk = get_private_jwk(&bsky_oauth)?;
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
        // A store for saving state data while the user is being redirected to the authorization server.
        state_store: MemoryStateStore::default(),
        // A store for saving session data.
        session_store: MemorySessionStore::default(),
    };

    // let Ok(client) = OAuthClient::new(config) else {
    //     panic!("failed to create oauth client");
    // };

    let client = OAuthClient::new(config).wrap_err("failed to create oauth client")?;

    Ok(client)
}
