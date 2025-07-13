use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Parser;
use fixtures::{db, run_server, FixtureArgs};
use serde::Serialize;
use serde_json::json;
use sqlx::{Pool, Sqlite};
use tracing::info;
use uuid::Uuid;

/// PDS (Personal Data Server) fixture server
#[derive(Parser, Debug)]
#[clap(name = "pds-fixture")]
struct Cli {
    #[clap(flatten)]
    common: FixtureArgs,
}

// Server state to hold configured responses
#[derive(Clone)]
struct AppState {
    port: u16,
    db: Pool<Sqlite>,
    avatar_cdn_url: String,
}

#[derive(Serialize)]
struct OAuthRedirectParams<'a> {
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // We don't have any specific env vars to check for the PDS fixture

    // Initialize the in-memory database
    let db = db::init_database().await?;

    let state = AppState {
        port: args.common.port,
        db,
        avatar_cdn_url: std::env::var("AVATAR_CDN_URL")
            .unwrap_or_else(|_| "http://localhost:3003".to_string()),
    };

    let app = Router::new()
        // OAuth endpoints
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server),
        )
        .route("/.well-known/jwks.json", get(jwks))
        // OAuth protocol endpoints
        .route("/xrpc/com.atproto.server.authorize", get(authorize))
        .route(
            "/xrpc/com.atproto.server.pushAuthorization",
            post(push_authorization),
        )
        .route("/xrpc/com.atproto.server.getToken", post(get_token))
        // PDS XRPC endpoints
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
        .with_state(state);

    run_server(args.common, app).await
}

// Handler implementations

async fn get_profile(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Check which actor is being requested
    let default_actor = "did:plc:abcdefg".to_string();
    let actor = params.get("actor").unwrap_or(&default_actor);

    match actor.as_str() {
        "did:plc:bbbbb" => Json(json!({
            "did": "did:plc:bbbbb",
            "handle": "fixture-user2.test",
            "displayName": "Fixture User 2",
            "description": "This is the second test user from the fixture server",
            "avatar": format!("{}/img/avatar/plain/did:plc:bbbbb/bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
            "indexedAt": "2025-03-14T12:00:00.000Z"
        })),
        _ => Json(json!({
            "did": "did:plc:abcdefg",
            "handle": "fixture-user.test",
            "displayName": "Fixture User",
            "description": "This is a test user from the fixture server",
            "avatar": format!("{}/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
            "indexedAt": "2025-03-14T12:00:00.000Z"
        })),
    }
}

async fn oauth_protected_resource(State(state): State<AppState>) -> impl IntoResponse {
    let base_url = format!("http://localhost:{}", state.port);
    info!("PDS: Returning oauth-protected-resource with auth server: {base_url}");
    Json(json!({
        // This matches what the real API returns - has to contain an array
        "authorization_servers": [base_url],
        "resource": base_url,
        "scopes_supported": ["read", "write", "profile", "email"],
        "response_types_supported": ["code"]
    }))
}

async fn get_record(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Check what collection is being requested
    let default_collection = "app.bsky.actor.profile".to_string();
    let collection = params.get("collection").unwrap_or(&default_collection);
    let repo = params
        .get("repo")
        .unwrap_or(&"did:plc:abcdefg".to_string())
        .to_string();

    match (collection.as_str(), repo.as_str()) {
        // Handle first user profile record
        ("app.bsky.actor.profile", "did:plc:abcdefg") => (
            axum::http::StatusCode::OK,
            Json(json!({
                "uri": "at://did:plc:abcdefg/app.bsky.actor.profile/self",
                "cid": "bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u",
                "value": {
                    "$type": "app.bsky.actor.profile",
                    "displayName": "Fixture User",
                    "description": "This is a test user from the fixture server",
                    "avatar": {
                        "$type": "blob",
                        "ref": {
                            "$link": "bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u"
                        },
                        "mimeType": "image/jpeg",
                        "size": 12345
                    }
                }
            })),
        ),
        // Handle second user profile record
        ("app.bsky.actor.profile", "did:plc:bbbbb") => (
            axum::http::StatusCode::OK,
            Json(json!({
                "uri": "at://did:plc:bbbbb/app.bsky.actor.profile/self",
                "cid": "bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u",
                "value": {
                    "$type": "app.bsky.actor.profile",
                    "displayName": "Fixture User 2",
                    "description": "This is the second test user from the fixture server",
                    "avatar": {
                        "$type": "blob",
                        "ref": {
                            "$link": "bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u"
                        },
                        "mimeType": "image/jpeg",
                        "size": 12345
                    }
                }
            })),
        ),
        // Handle first user's custom collection for original profile pictures
        ("blue.pfp.unmodifiedPfp", "did:plc:abcdefg") => (
            axum::http::StatusCode::OK,
            Json(json!({
                "uri": "at://did:plc:abcdefg/blue.pfp.unmodifiedPfp/self",
                "cid": "bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u",
                "value": {
                    "avatar": {
                        "$type": "blob",
                        "ref": {
                            "$link": "bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u"
                        },
                        "mimeType": "image/jpeg",
                        "size": 12345
                    },
                    "createdAt": "2025-03-15T12:00:00.000Z"
                }
            })),
        ),
        // Handle second user's custom collection for original profile pictures
        ("blue.pfp.unmodifiedPfp", "did:plc:bbbbb") => (
            axum::http::StatusCode::OK,
            Json(json!({
                "uri": "at://did:plc:bbbbb/blue.pfp.unmodifiedPfp/self",
                "cid": "bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u",
                "value": {
                    "avatar": {
                        "$type": "blob",
                        "ref": {
                            "$link": "bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u"
                        },
                        "mimeType": "image/jpeg",
                        "size": 12345
                    },
                    "createdAt": "2025-03-15T12:00:00.000Z"
                }
            })),
        ),
        // Default to not found for other collections
        _ => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Record not found",
                "message": format!("No record found for collection: {} in repo: {}", collection, repo)
            })),
        ),
    }
}

async fn get_blob(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Check which blob is being requested
    let cid = params.get("cid").unwrap_or(&"".to_string()).to_string();

    match cid.as_str() {
        // First user's profile picture (blue pixel)
        "bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u" => {
            // Blue pixel
            let image_data: &[u8] = &[
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
                0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
                0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
                0xD7, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
                0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
            ];

            (
                [(axum::http::header::CONTENT_TYPE, "image/png")],
                image_data,
            )
        }
        // Second user's profile picture (red pixel)
        "bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u" => {
            // Red pixel
            let image_data: &[u8] = &[
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
                0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
                0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
                0xD7, 0x63, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x7B, 0x38,
                0xAF, 0x7A, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
            ];

            (
                [(axum::http::header::CONTENT_TYPE, "image/png")],
                image_data,
            )
        }
        // Default case for unknown CIDs (grey pixel)
        _ => {
            // Grey pixel
            let image_data: &[u8] = &[
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
                0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
                0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
                0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
                0xB0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
            ];

            (
                [(axum::http::header::CONTENT_TYPE, "image/png")],
                image_data,
            )
        }
    }
}

async fn refresh_session(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Check the refresh token to determine which user is refreshing
    let refresh_token = params
        .get("refreshJwt")
        .unwrap_or(&"".to_string())
        .to_string();

    if refresh_token.contains("user2") {
        // Return second user's session
        Json(json!({
            "accessJwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmJiYmJiIiwiZXhwIjoxNzA5MTIzNDU2fQ.fixture-user2",
            "refreshJwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmJiYmJiIiwiZXhwIjoxNzA5MTIzNDU2fQ.refresh-fixture-user2",
            "handle": "fixture-user2.test",
            "did": "did:plc:bbbbb"
        }))
    } else {
        // Default to first user's session
        Json(json!({
            "accessJwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.fixture",
            "refreshJwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.refresh-fixture",
            "handle": "fixture-user.test",
            "did": "did:plc:abcdefg"
        }))
    }
}

async fn upload_blob() -> impl IntoResponse {
    Json(json!({
        "blob": {
            "$type": "blob",
            "ref": {
                "$link": "bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u"
            },
            "mimeType": "image/jpeg",
            "size": 12345
        }
    }))
}

async fn put_record() -> impl IntoResponse {
    Json(json!({
        "uri": "at://did:plc:abcdefg/app.bsky.actor.profile/self",
        "cid": "bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u"
    }))
}

// OAuth authorization server metadata endpoint
async fn oauth_authorization_server(State(state): State<AppState>) -> impl IntoResponse {
    let base_url = format!("http://localhost:{}", state.port);
    info!("PDS: Returning oauth-authorization-server metadata");

    Json(json!({
        "issuer": base_url,
        "pushed_authorization_request_endpoint": format!("{}/xrpc/com.atproto.server.pushAuthorization", base_url),
        "authorization_endpoint": format!("{}/xrpc/com.atproto.server.authorize", base_url),
        "token_endpoint": format!("{}/xrpc/com.atproto.server.getToken", base_url),
        "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
        "scopes_supported": ["read", "write", "profile", "email", "atproto", "transition:generic"],
        "response_types_supported": ["code"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "RS256"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "require_pushed_authorization_requests": false,
        "client_id_schemes_supported": ["did"]
    }))
}

// OAuth endpoints implementations

// OAuth authorization endpoint - usually this would show a login UI
// For testing, we'll auto-authorize and redirect to the callback
use axum::extract::Query;

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct AuthorizeQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_type: Option<String>,
    request_uri: Option<String>,
}

// The authorization endpoint is what the browser gets redirected to
async fn authorize(
    State(app_state): State<AppState>,
    Query(params): Query<AuthorizeQuery>,
    axum::extract::Query(all_params): axum::extract::Query<
        std::collections::HashMap<String, String>,
    >,
) -> impl IntoResponse {
    // Handle PAR flow where request_uri is provided instead of direct parameters
    let (redirect_uri, auth_code, _scope, _code_challenge, state) = if let Some(request_uri) =
        &params.request_uri
    {
        info!("PDS: Handling PAR authorization with request_uri: {request_uri}");

        // Look up the PAR request from the database
        let par_data = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            r#"
            SELECT client_id, redirect_uri, state, code_challenge, code_challenge_method, scope
            FROM par_requests 
            WHERE request_uri = ? AND expires_at > ?
            "#,
        )
        .bind(request_uri)
        .bind(chrono::Utc::now().timestamp())
        .fetch_optional(&app_state.db)
        .await;

        match par_data {
            Ok(Some((
                client_id,
                redirect_uri,
                state,
                code_challenge,
                _code_challenge_method,
                scope,
            ))) => {
                info!("PDS: Found PAR request for client_id: {client_id}, scope: {scope}");

                // Determine user based on scope
                let (auth_code, user_did, user_handle) = if scope.contains("fixture-user2.test") {
                    info!("PDS: PAR flow - Authorizing as fixture-user2.test");
                    (
                        format!("fixture_auth_code_{}", Uuid::new_v4()),
                        "did:plc:bbbbb".to_string(),
                        "fixture-user2.test".to_string(),
                    )
                } else {
                    info!("PDS: PAR flow - Authorizing as fixture-user.test");
                    (
                        format!("fixture_auth_code_{}", Uuid::new_v4()),
                        "did:plc:abcdefg".to_string(),
                        "fixture-user.test".to_string(),
                    )
                };

                // Store the authorization code in the database
                let expires_at = chrono::Utc::now().timestamp() + 600; // 10 minutes expiration
                let _ = sqlx::query(
                    r#"
                    INSERT INTO auth_codes (
                        code, request_uri, client_id, redirect_uri, user_did, 
                        user_handle, scope, code_challenge, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&auth_code)
                .bind(request_uri)
                .bind(&client_id)
                .bind(&redirect_uri)
                .bind(&user_did)
                .bind(&user_handle)
                .bind(&scope)
                .bind(&code_challenge)
                .bind(expires_at)
                .execute(&app_state.db)
                .await;

                (redirect_uri, auth_code, scope, code_challenge, state)
            }
            Ok(None) => {
                tracing::error!("PAR request not found or expired: {request_uri}");
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_request",
                        "error_description": "Invalid or expired request_uri"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!("Failed to fetch PAR request: {}", e);
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "server_error",
                        "error_description": "Failed to process authorization request"
                    })),
                )
                    .into_response();
            }
        }
    } else {
        // Traditional OAuth flow
        let redirect_uri = params
            .redirect_uri
            .clone()
            .unwrap_or_else(|| "http://localhost:3000/oauth/bsky/callback".to_string());
        let client_id = params.client_id.clone().unwrap_or_default();
        let code_challenge = params.code_challenge.clone();

        info!("PDS: Handling traditional OAuth authorization with redirect_uri: {redirect_uri}");

        // The handle is passed as a scope in the form "profile.handle:fixture-user.test"
        let scope = all_params
            .get("scope")
            .unwrap_or(&"".to_string())
            .to_string();
        info!("PDS: OAuth scope: {scope}");

        // Determine which user is being authorized based on the handle in the scope
        let (auth_code, user_did, user_handle) = if scope.contains("fixture-user2.test") {
            info!("PDS: Authorizing as fixture-user2.test");
            (
                format!("fixture_auth_code_{}", Uuid::new_v4()),
                "did:plc:bbbbb".to_string(),
                "fixture-user2.test".to_string(),
            )
        } else {
            info!("PDS: Authorizing as fixture-user.test");
            (
                format!("fixture_auth_code_{}", Uuid::new_v4()),
                "did:plc:abcdefg".to_string(),
                "fixture-user.test".to_string(),
            )
        };

        // Store the authorization code in the database
        let expires_at = chrono::Utc::now().timestamp() + 600; // 10 minutes expiration
        let _ = sqlx::query(
            r#"
            INSERT INTO auth_codes (
                code, request_uri, client_id, redirect_uri, user_did, 
                user_handle, scope, code_challenge, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&auth_code)
        .bind(None::<String>) // No request_uri for traditional flow
        .bind(&client_id)
        .bind(&redirect_uri)
        .bind(&user_did)
        .bind(&user_handle)
        .bind(&scope)
        .bind(&code_challenge)
        .bind(expires_at)
        .execute(&app_state.db)
        .await;

        (
            redirect_uri,
            auth_code,
            scope,
            code_challenge,
            params.state.clone(),
        )
    };

    // For fixtures, we'll auto-authorize and redirect back with a code
    let redirect_params = OAuthRedirectParams {
        code: &auth_code,
        state: state.as_deref(),
    };
    let query_string = serde_urlencoded::to_string(&redirect_params).unwrap(); // SAFETY: We are in fixtures so a panic is fine
    let redirect_url = format!("{redirect_uri}?{query_string}");

    info!("PDS: Redirecting to: {redirect_url}");

    // Redirect to callback URL with auth code
    axum::response::Redirect::to(&redirect_url).into_response()
}

// The pushed authorization request endpoint
async fn push_authorization(
    State(state): State<AppState>,
    axum::extract::Form(params): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    info!("PDS: Handling pushed authorization request");

    // Extract parameters
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    let redirect_uri = params
        .get("redirect_uri")
        .cloned()
        .unwrap_or_else(|| "http://localhost:3000/oauth/bsky/callback".to_string());
    let state_param = params.get("state").cloned();
    let code_challenge = params.get("code_challenge").cloned();
    let code_challenge_method = params.get("code_challenge_method").cloned();
    let scope = params.get("scope").cloned().unwrap_or_default();

    info!("PDS: Push authorization scope: {scope}");

    // Generate a unique request URI
    let request_uri = format!("urn:fixture:auth:{}", Uuid::new_v4());

    // Store the PAR request in the database
    let expires_at = chrono::Utc::now().timestamp() + 60; // 60 seconds expiration

    let result = sqlx::query(
        r#"
        INSERT INTO par_requests (
            request_uri, client_id, redirect_uri, state, 
            code_challenge, code_challenge_method, scope, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&request_uri)
    .bind(&client_id)
    .bind(&redirect_uri)
    .bind(&state_param)
    .bind(&code_challenge)
    .bind(&code_challenge_method)
    .bind(&scope)
    .bind(expires_at)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!("PDS: Stored PAR request with URI: {request_uri}");
            // Return a request URI that the client will redirect to
            // PAR typically returns 201 Created
            (
                axum::http::StatusCode::CREATED,
                Json(json!({
                    "request_uri": request_uri,
                    "expires_in": 60
                })),
            )
        }
        Err(e) => {
            tracing::error!("Failed to store PAR request: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to store authorization request"
                })),
            )
        }
    }
}

// The token endpoint
async fn get_token(
    State(state): State<AppState>,
    axum::extract::Form(params): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    info!("PDS: Handling token request");

    // Extract the authorization code
    let code = params.get("code").cloned().unwrap_or_default();

    if code.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Missing authorization code"
            })),
        )
            .into_response();
    }

    // Look up the authorization code from the database
    let auth_code_data = sqlx::query_as::<_, (String, String, String, String)>(
        r#"
        SELECT user_did, user_handle, scope, redirect_uri
        FROM auth_codes 
        WHERE code = ? AND expires_at > ?
        "#,
    )
    .bind(&code)
    .bind(chrono::Utc::now().timestamp())
    .fetch_optional(&state.db)
    .await;

    match auth_code_data {
        Ok(Some((user_did, user_handle, scope, _redirect_uri))) => {
            info!("PDS: Found valid auth code for user: {user_handle} ({user_did})");

            // Delete the used authorization code
            let _ = sqlx::query("DELETE FROM auth_codes WHERE code = ?")
                .bind(&code)
                .execute(&state.db)
                .await;

            // Generate valid JWT tokens based on the user
            let base_url = format!("http://localhost:{}", state.port);
            let now = chrono::Utc::now().timestamp();
            let exp = now + 3600; // 1 hour expiration

            // Create JWT claims for access token
            let access_claims = json!({
                "iss": base_url,
                "aud": user_did.clone(),
                "sub": user_did.clone(),
                "iat": now,
                "exp": exp,
                "scope": scope.clone()
            });

            // Create JWT claims for refresh token (longer expiration)
            let refresh_claims = json!({
                "iss": base_url,
                "aud": user_did.clone(),
                "sub": user_did.clone(),
                "iat": now,
                "exp": now + 2592000, // 30 days expiration
                "scope": scope.clone(),
                "jti": format!("refresh_{}", Uuid::new_v4())
            });

            // For fixtures, we'll use simple base64-encoded JWTs with a test signature
            // In production, these would be properly signed with the PDS's private key
            let header = URL_SAFE_NO_PAD.encode(
                json!({"alg": "ES256", "typ": "JWT", "kid": "fixture-key-1"})
                    .to_string()
                    .as_bytes(),
            );

            let access_payload = URL_SAFE_NO_PAD.encode(access_claims.to_string().as_bytes());

            let refresh_payload = URL_SAFE_NO_PAD.encode(refresh_claims.to_string().as_bytes());

            // Create test signature (in production this would be a real ES256 signature)
            let test_signature = if user_handle == "fixture-user2.test" {
                "fixture-sig-user2"
            } else {
                "fixture-sig-user1"
            };
            let signature = URL_SAFE_NO_PAD.encode(test_signature.as_bytes());

            let access_token = format!("{header}.{access_payload}.{signature}");
            let refresh_token = format!("{header}.{refresh_payload}.{signature}");

            info!("PDS: Issuing JWT tokens for {}", user_handle);

            // Return a properly structured token response
            (
                axum::http::StatusCode::OK,
                Json(json!({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": scope,
                    "sub": user_did,
                })),
            )
                .into_response()
        }
        Ok(None) => {
            tracing::error!("Authorization code not found or expired: {code}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_grant",
                    "error_description": "Invalid or expired authorization code"
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to fetch authorization code: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "server_error",
                    "error_description": "Failed to process token request"
                })),
            )
                .into_response()
        }
    }
}

// JWKS endpoint for JWT verification
async fn jwks() -> impl IntoResponse {
    info!("PDS: Returning JWKS for token verification");

    // Return a test JWKS with a dummy ES256 key for fixture testing
    // In production, this would contain the actual public keys used to verify JWTs
    Json(json!({
        "keys": [
            {
                "kty": "EC",
                "use": "sig",
                "crv": "P-256",
                "kid": "fixture-key-1",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
                "alg": "ES256"
            }
        ]
    }))
}
