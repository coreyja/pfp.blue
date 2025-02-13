use axum::routing::get;

use crate::state::AppState;

pub fn routes(app_state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(root))
        .with_state(app_state)
}

async fn root() -> &'static str {
    "This is pfp.blue, welcome!"
}
