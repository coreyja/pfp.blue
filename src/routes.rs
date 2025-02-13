use axum::routing::get;

use crate::state::AppState;

mod bsky;

pub fn routes(app_state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(root))
        .route("/oauth/bsky/metadata.json", get(bsky::client_metadata))
        .with_state(app_state)
}

async fn root() -> &'static str {
    "This is pfp.blue, welcome!"
}
