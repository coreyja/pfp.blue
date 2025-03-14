use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use fixtures::{run_server, FixtureArgs};
use serde::{Deserialize, Serialize};
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
#[derive(Clone, Default)]
struct AppState {
    data: Arc<Mutex<Value>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    
    let state = AppState::default();

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
        .route("/.well-known/oauth-protected-resource", get(oauth_protected_resource))
        
        // PDS XRPC endpoints
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.server.refreshSession", post(refresh_session))
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        
        .with_state(state);

    run_server(args.common, app).await
}

// Handler implementations

async fn oauth_protected_resource() -> impl IntoResponse {
    Json(json!({
        "issuer": "https://pds-fixture:3000",
        "authorization_server": "https://pds-fixture:3000"
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
    ([(axum::http::header::CONTENT_TYPE, "image/jpeg")], image_data)
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