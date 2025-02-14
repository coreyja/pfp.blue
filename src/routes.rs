use atrium_xrpc_client::reqwest::ReqwestClientBuilder;
use axum::{response::IntoResponse, routing::get, Form};
use maud::html;

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
        input type="text" name="handle" placeholder="Enter your handle" {}

        button type="submit" { "Login" }
      }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
struct LoginForm {
    handle: String,
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
async fn login_post(form: Form<LoginForm>) -> impl IntoResponse {
    let handle = form.handle.clone();
    let handle = atrium_api::types::string::Handle::new(handle).unwrap();
    let client = ReqwestClientBuilder::new("https://bsky.social")
        .client(
            reqwest::ClientBuilder::new()
                .timeout(std::time::Duration::from_millis(1000))
                .use_rustls_tls()
                .build()
                .unwrap(),
        )
        .build();
    let did_doc = resolve_handle_to_did_document(&handle, client.into())
        .await
        .unwrap();

    html! {
      p { "DID Document: " (Debug(did_doc)) }
    }
}
