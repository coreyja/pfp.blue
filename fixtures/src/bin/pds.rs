use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use fixtures::{run_server, FixtureArgs};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tracing::info;

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
    data: Arc<Mutex<Value>>,
    port: u16,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(Value::Null)),
            port: 0,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // We don't have any specific env vars to check for the PDS fixture

    let mut state = AppState::default();
    state.port = args.common.port;

    // Load fixture data if provided
    if let Some(data_path) = &args.common.data {
        if data_path.exists() {
            let data = std::fs::read_to_string(data_path)?;
            let json_data: Value = serde_json::from_str(&data)?;
            *state.data.lock().unwrap() = json_data;
            info!("Loaded fixture data from {}", data_path.display());
        }
    }

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

async fn get_record() -> impl IntoResponse {
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
    }))
}

async fn get_blob() -> impl IntoResponse {
    // Return a small test image
    let image_data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
    (
        [(axum::http::header::CONTENT_TYPE, "image/jpeg")],
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
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
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
