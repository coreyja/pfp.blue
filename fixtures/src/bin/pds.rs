use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use fixtures::{run_server, FixtureArgs};
use serde::Serialize;
use serde_json::json;

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

    let state = AppState {
        port: args.common.port,
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
        .with_state(state);

    run_server(args.common, app).await
}

// Handler implementations

async fn oauth_protected_resource(State(state): State<AppState>) -> impl IntoResponse {
    let base_url = format!("http://localhost:{}", state.port);
    println!(
        "PDS: Returning oauth-protected-resource with auth server: {}",
        base_url
    );
    Json(json!({
        // This matches what the real API returns - has to contain an array
        "authorization_servers": [base_url]
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
    println!("PDS: Returning oauth-authorization-server metadata");

    Json(json!({
        "issuer": base_url,
        "pushed_authorization_request_endpoint": format!("{}/xrpc/com.atproto.server.pushAuthorization", base_url),
        "authorization_endpoint": format!("{}/xrpc/com.atproto.server.authorize", base_url),
        "token_endpoint": format!("{}/xrpc/com.atproto.server.getToken", base_url),
        "scopes_supported": ["read", "write", "profile", "email"]
    }))
}

// OAuth endpoints implementations

// OAuth authorization endpoint - usually this would show a login UI
// For testing, we'll auto-authorize and redirect to the callback
use axum::extract::Query;

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    state: Option<String>,

    code_challenge: Option<String>,

    code_challenge_method: Option<String>,

    response_type: Option<String>,
}

// The authorization endpoint is what the browser gets redirected to
async fn authorize(
    Query(params): Query<AuthorizeQuery>,
    axum::extract::Query(all_params): axum::extract::Query<
        std::collections::HashMap<String, String>,
    >,
) -> impl IntoResponse {
    println!(
        "PDS: Handling OAuth authorization request with redirect_uri: {}",
        params.redirect_uri
    );

    // The handle is passed as a scope in the form "profile.handle:fixture-user.test"
    let scope = all_params
        .get("scope")
        .unwrap_or(&"".to_string())
        .to_string();
    println!("PDS: OAuth scope: {}", scope);

    // Determine which user is being authorized based on the handle in the scope
    let auth_code = if scope.contains("fixture-user2.test") {
        println!("PDS: Authorizing as fixture-user2.test");
        "fixture_auth_code_user2"
    } else {
        println!("PDS: Authorizing as fixture-user.test");
        "fixture_auth_code_12345"
    };

    // For fixtures, we'll auto-authorize and redirect back with a code
    let redirect_params = OAuthRedirectParams {
        code: auth_code,
        state: params.state.as_deref(),
    };
    let query_string = serde_urlencoded::to_string(&redirect_params)?;
    let redirect_url = format!("{}?{}", params.redirect_uri, query_string);

    println!("PDS: Redirecting to: {}", redirect_url);

    // Redirect to callback URL with auth code
    axum::response::Redirect::to(&redirect_url)
}

// The pushed authorization request endpoint
async fn push_authorization(
    axum::extract::Form(params): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    println!("PDS: Handling pushed authorization request");

    // The handle is passed as a scope in the form "profile.handle:fixture-user.test"
    let scope = params.get("scope").unwrap_or(&"".to_string()).to_string();
    println!("PDS: Push authorization scope: {}", scope);

    // Determine which user is being authorized based on the handle in the scope
    let request_uri = if scope.contains("fixture-user2.test") {
        println!("PDS: Using request URI for fixture-user2.test");
        "urn:fixture:auth:user2:12345"
    } else {
        println!("PDS: Using request URI for fixture-user.test");
        "urn:fixture:auth:12345"
    };

    // Return a request URI that the client will redirect to
    Json(json!({
        "request_uri": request_uri,
        "expires_in": 60
    }))
}

// The token endpoint
async fn get_token(
    axum::extract::Form(params): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    println!("PDS: Handling token request");

    // Check various params to determine which user is authenticating
    let code = params
        .get("code")
        .unwrap_or(&"fixture_auth_code_12345".to_string())
        .to_string();
    let request_uri = params
        .get("request_uri")
        .unwrap_or(&"".to_string())
        .to_string();

    // Check both code and request_uri for user2 identifiers
    let is_user2 = code == "fixture_auth_code_user2" || request_uri.contains("user2");

    if is_user2 {
        println!("PDS: Issuing tokens for fixture-user2.test");
        // Return tokens for the second user
        Json(json!({
            "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmJiYmJiIiwiZXhwIjoxNzA5MTIzNDU2fQ.fixture-user2",
            "refresh_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmJiYmJiIiwiZXhwIjoxNzA5MTIzNDU2fQ.refresh-fixture-user2",
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "read write profile email"
        }))
    } else {
        println!("PDS: Issuing tokens for fixture-user.test");
        // Default to first user's tokens
        Json(json!({
            "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.fixture",
            "refresh_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.refresh-fixture",
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "read write profile email"
        }))
    }
}
