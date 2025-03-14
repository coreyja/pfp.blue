use axum::{
    extract::{Path, Query},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use fixtures::{run_server, FixtureArgs};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tracing::info;

/// AppView fixture server
#[derive(Parser, Debug)]
#[clap(name = "appview-fixture")]
struct Cli {
    #[clap(flatten)]
    common: FixtureArgs,
}

// Server state to hold configured responses
#[derive(Clone, Default)]
struct AppState {
    data: Arc<Mutex<Value>>,
}

#[derive(Debug, Deserialize)]
struct HandleResolveParams {
    handle: String,
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
        // AppView XRPC endpoints
        .route("/xrpc/com.atproto.identity.resolveHandle", get(resolve_handle))
        .route("/xrpc/app.bsky.actor.getProfile", get(get_profile))
        .route("/xrpc/app.bsky.actor.getProfiles", get(get_profiles))
        .route("/xrpc/app.bsky.actor.searchActors", get(search_actors))
        
        .with_state(state);

    run_server(args.common, app).await
}

// Handler implementations

async fn resolve_handle(Query(params): Query<HandleResolveParams>) -> impl IntoResponse {
    let did = match params.handle.as_str() {
        "fixture-user.test" => "did:plc:abcdefg",
        _ => "did:plc:unknown",
    };
    
    Json(json!({
        "did": did
    }))
}

async fn get_profile() -> impl IntoResponse {
    Json(json!({
        "did": "did:plc:abcdefg",
        "handle": "fixture-user.test",
        "displayName": "Fixture User",
        "description": "This is a test user from the fixture server",
        "avatar": "https://avatar-fixture.test/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg",
        "indexedAt": "2025-03-14T12:00:00.000Z"
    }))
}

async fn get_profiles() -> impl IntoResponse {
    Json(json!({
        "profiles": [
            {
                "did": "did:plc:abcdefg",
                "handle": "fixture-user.test",
                "displayName": "Fixture User",
                "description": "This is a test user from the fixture server",
                "avatar": "https://avatar-fixture.test/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg",
                "indexedAt": "2025-03-14T12:00:00.000Z"
            }
        ]
    }))
}

async fn search_actors() -> impl IntoResponse {
    Json(json!({
        "actors": [
            {
                "did": "did:plc:abcdefg",
                "handle": "fixture-user.test",
                "displayName": "Fixture User",
                "description": "This is a test user from the fixture server",
                "avatar": "https://avatar-fixture.test/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg",
                "indexedAt": "2025-03-14T12:00:00.000Z"
            }
        ]
    }))
}