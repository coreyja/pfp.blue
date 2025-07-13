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
    let avatar_cdn_url = require_env_var("AVATAR_CDN_URL")?;

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
        "fixture-user2.test" => "did:plc:bbbbb",
        _ => "did:plc:unknown",
    };

    Json(json!({
        "did": did
    }))
}

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

async fn get_profiles(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Check which actors are being requested
    let actors = params.get("actors");

    let mut profiles = Vec::new();

    // Add default user profile
    if actors.is_none() || actors.unwrap().contains("did:plc:abcdefg") {
        profiles.push(json!({
            "did": "did:plc:abcdefg",
            "handle": "fixture-user.test",
            "displayName": "Fixture User",
            "description": "This is a test user from the fixture server",
            "avatar": format!("{}/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
            "indexedAt": "2025-03-14T12:00:00.000Z"
        }));
    }

    // Add second user profile if requested
    if actors.is_none() || actors.unwrap().contains("did:plc:bbbbb") {
        profiles.push(json!({
            "did": "did:plc:bbbbb",
            "handle": "fixture-user2.test",
            "displayName": "Fixture User 2",
            "description": "This is the second test user from the fixture server",
            "avatar": format!("{}/img/avatar/plain/did:plc:bbbbb/bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
            "indexedAt": "2025-03-14T12:00:00.000Z"
        }));
    }

    Json(json!({
        "profiles": profiles
    }))
}

async fn search_actors(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // Check if a term is being searched for
    let empty_string = "".to_string();
    let term = params.get("term").unwrap_or(&empty_string);

    let mut actors = Vec::new();

    // Add first user if matching search term
    if term.is_empty() || term.contains("fixture-user") || term.contains("fixture") {
        actors.push(json!({
            "did": "did:plc:abcdefg",
            "handle": "fixture-user.test",
            "displayName": "Fixture User",
            "description": "This is a test user from the fixture server",
            "avatar": format!("{}/img/avatar/plain/did:plc:abcdefg/bafyreib3hg56hnxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
            "indexedAt": "2025-03-14T12:00:00.000Z"
        }));
    }

    // Add second user if matching search term
    if term.is_empty() || term.contains("fixture-user2") || term.contains("fixture") {
        actors.push(json!({
            "did": "did:plc:bbbbb",
            "handle": "fixture-user2.test",
            "displayName": "Fixture User 2",
            "description": "This is the second test user from the fixture server",
            "avatar": format!("{}/img/avatar/plain/did:plc:bbbbb/bafyreic2hxcysikiv5rsr2okgujajrjrpz4kpf7se52jgygyz7d7u@jpeg", state.avatar_cdn_url),
            "indexedAt": "2025-03-14T12:00:00.000Z"
        }));
    }

    Json(json!({
        "actors": actors
    }))
}
