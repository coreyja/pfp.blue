use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use fixtures::{run_server, FixtureArgs};
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

    match collection.as_str() {
        // Handle profile record
        "app.bsky.actor.profile" => (
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
        // Handle our custom collection for original profile pictures
        "blue.pfp.unmodifiedPfp" => (
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
        // Default to not found for other collections
        _ => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Record not found",
                "message": format!("No record found for collection: {}", collection)
            })),
        ),
    }
}

async fn get_blob() -> impl IntoResponse {
    // Create a simple colored square image (1x1 pixel PNG)
    // This is a valid PNG image representing a blue pixel
    let image_data: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
        0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8,
        0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB0, 0x00, 0x00, 0x00,
        0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    (
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        image_data,
    )
}

async fn refresh_session() -> impl IntoResponse {
    Json(json!({
        "accessJwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.fixture",
        "refreshJwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.refresh-fixture",
        "handle": "fixture-user.test",
        "did": "did:plc:abcdefg"
    }))
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
struct AuthorizeQuery {
    #[allow(dead_code)]
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    #[allow(dead_code)]
    code_challenge: Option<String>,
    #[allow(dead_code)]
    code_challenge_method: Option<String>,
    #[allow(dead_code)]
    response_type: Option<String>,
}

// The authorization endpoint is what the browser gets redirected to
async fn authorize(Query(params): Query<AuthorizeQuery>) -> impl IntoResponse {
    println!(
        "PDS: Handling OAuth authorization request with redirect_uri: {}",
        params.redirect_uri
    );

    // For fixtures, we'll auto-authorize and redirect back with a code
    let redirect_url = if let Some(state) = params.state {
        // Include state if provided
        format!(
            "{}?code=fixture_auth_code_12345&state={}",
            params.redirect_uri, state
        )
    } else {
        // Just code if no state
        format!("{}?code=fixture_auth_code_12345", params.redirect_uri)
    };

    println!("PDS: Redirecting to: {}", redirect_url);

    // Redirect to callback URL with auth code
    axum::response::Redirect::to(&redirect_url)
}

// The pushed authorization request endpoint
async fn push_authorization() -> impl IntoResponse {
    println!("PDS: Handling pushed authorization request");

    // Return a request URI that the client will redirect to
    Json(json!({
        "request_uri": "urn:fixture:auth:12345",
        "expires_in": 60
    }))
}

// The token endpoint
async fn get_token() -> impl IntoResponse {
    println!("PDS: Handling token request");

    // Return tokens
    Json(json!({
        "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.fixture",
        "refresh_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkaWQ6cGxjOmFiY2RlZmciLCJleHAiOjE3MDkxMjM0NTZ9.refresh-fixture",
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": "read write profile email"
    }))
}
