use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use fixtures::{require_env_var, run_server, FixtureArgs};
use serde::Deserialize;
use serde_json::json;

/// AppView fixture server
#[derive(Parser, Debug)]
#[clap(name = "appview-fixture")]
struct Cli {
    #[clap(flatten)]
    common: FixtureArgs,
}

// Server state to hold configured responses
#[derive(Clone)]
struct AppState {
    avatar_cdn_url: String,
}

#[derive(Debug, Deserialize)]
struct HandleResolveParams {
    handle: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // Get URL of the Avatar CDN
    let avatar_cdn_url = require_env_var("AVATAR_CDN_URL", args.common.force)?;

    let state = AppState { avatar_cdn_url };

    let app = Router::new()
        // AppView XRPC endpoints
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle),
        )
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
        "fixture-user2.test" => "did:plc:bbbbbb",
        _ => "did:plc:unknown",
    };

    Json(json!({
        "did": did
    }))
}

async fn get_profile(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "did": "did:plc:abcdefg",
        "handle": "fixture-user.test",
        "displayName": "Fixture User",
        "description": "This is a test user from the fixture server",
        "avatar": format!("{}/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
        "indexedAt": "2025-03-14T12:00:00.000Z"
    }))
}

async fn get_profiles(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "profiles": [
            {
                "did": "did:plc:abcdefg",
                "handle": "fixture-user.test",
                "displayName": "Fixture User",
                "description": "This is a test user from the fixture server",
                "avatar": format!("{}/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
                "indexedAt": "2025-03-14T12:00:00.000Z"
            }
        ]
    }))
}

async fn search_actors(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "actors": [
            {
                "did": "did:plc:abcdefg",
                "handle": "fixture-user.test",
                "displayName": "Fixture User",
                "description": "This is a test user from the fixture server",
                "avatar": format!("{}/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
                "indexedAt": "2025-03-14T12:00:00.000Z"
            }
        ]
    }))
}
