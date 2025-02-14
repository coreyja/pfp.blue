use atrium_api::types::string::Did;
use axum::extract::State;
use axum::{response::IntoResponse, routing::get, Form};
use maud::html;

use crate::did::{document_to_auth_server_metadata, resolve_did_to_document};
use crate::{did::resolve_handle_to_did_document, state::AppState};

mod bsky;

pub fn routes(app_state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(root))
        .route("/login", get(login).post(login_post))
        .route("/oauth/bsky/metadata.json", get(bsky::client_metadata))
        .with_state(app_state)
}

async fn root() -> &'static str {
    "This is pfp.blue, welcome!"
}

async fn login() -> impl IntoResponse {
    maud::html! {
      form action="/login" method="post" {
        input type="text" name="handle_or_did" placeholder="Enter your handle or DID" {}

        button type="submit" { "Login" }
      }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct LoginForm {
    handle_or_did: String,
}

use maud::{Escaper, Render};
use std::fmt;
use std::fmt::Write as _;

/// Renders the given value using its `Debug` implementation.
struct Debug<T: fmt::Debug>(T);

impl<T: fmt::Debug> Render for Debug<T> {
    fn render_to(&self, output: &mut String) {
        let mut escaper = Escaper::new(output);
        write!(escaper, "{:?}", self.0).unwrap();
    }
}

#[axum_macros::debug_handler]
async fn login_post(State(state): State<AppState>, form: Form<LoginForm>) -> impl IntoResponse {
    let did_doc = if form.handle_or_did.starts_with("did:") {
        let did = Did::new(form.handle_or_did.clone()).unwrap();
        resolve_did_to_document(&did, state.bsky_client.clone())
            .await
            .unwrap()
    } else {
        let handle = form.handle_or_did.clone();
        let handle = atrium_api::types::string::Handle::new(handle).unwrap();
        resolve_handle_to_did_document(&handle, state.bsky_client.clone())
            .await
            .unwrap()
    };

    let auth_server_metadata =
        document_to_auth_server_metadata(&did_doc, state.bsky_client.clone())
            .await
            .unwrap();

    html! {
      p { "DID Document: " (Debug(did_doc)) }
      p { "Auth Server Metadata: " (Debug(auth_server_metadata)) }
    }
}
