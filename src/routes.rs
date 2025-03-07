use atrium_api::types::string::Did;
use axum::extract::State;
use axum::{response::IntoResponse, routing::get, Form};
use maud::html;
use tower_cookies::{Cookie, Cookies};

use crate::did::{document_to_auth_server_metadata, resolve_did_to_document};
use crate::state::AppState;

mod bsky;

pub fn routes(app_state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(root))
        .route("/me", get(bsky::profile))
        .route("/login", get(login).post(login_post))
        .route("/logout", get(logout))
        // Bluesky OAuth routes
        .route("/oauth/bsky/metadata.json", get(bsky::client_metadata))
        .route("/oauth/bsky/authorize", get(bsky::authorize))
        .route("/oauth/bsky/callback", get(bsky::callback))
        .route("/oauth/bsky/token", get(bsky::get_token))
        .route("/oauth/bsky/revoke", get(bsky::revoke_token))
        // Add trace layer for debugging
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app_state)
}

async fn root() -> impl IntoResponse {
    maud::html! {
        h1 { "pfp.blue" }
        p { "Welcome to pfp.blue!" }

        div {
            p { "Your profile page:" }
            a href="/me" { "View Your Profile" }

            p { "Or login:" }
            a href="/login" { "Login" }
        }
    }
}

async fn login(State(state): State<AppState>) -> impl IntoResponse {
    maud::html! {
      form action="/login" method="post" {
        input type="text" name="handle_or_did" placeholder="Enter your handle or DID" {}

        button type="submit" { "Login" }
      }

      hr {}

      h2 { "Login with Bluesky" }
      p { "Enter your Bluesky handle or DID:" }
      form action="/oauth/bsky/authorize" method="get" {
        input type="text" name="did" placeholder="Enter your handle or DID" {}
        input type="hidden" name="state" value="from_login_page" {}

        button type="submit" { "Login with Bluesky" }
      }

      hr {}
      p { "Debug Info:" }
      p { "Client ID: " (state.client_id()) }
      p { "Redirect URI: " (state.redirect_uri()) }
      p { "Domain: " (state.domain) }
      p { "Protocol: " (state.protocol) }
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
    // First, determine if input is a handle or DID and resolve to a DID
    let did = if form.handle_or_did.starts_with("did:") {
        // Input is already a DID
        match Did::new(form.handle_or_did.clone()) {
            Ok(did) => did,
            Err(_) => {
                return html! {
                    p { "Invalid DID format" }
                };
            }
        }
    } else {
        // Input is a handle, resolve to DID
        match atrium_api::types::string::Handle::new(form.handle_or_did.clone()) {
            Ok(handle) => {
                match crate::did::resolve_handle_to_did(&handle, state.bsky_client.clone()).await {
                    Ok(did) => did,
                    Err(err) => {
                        return html! {
                            p { "Failed to resolve handle to DID: " (err) }
                        };
                    }
                }
            }
            Err(_) => {
                return html! {
                    p { "Invalid handle format" }
                };
            }
        }
    };

    // Now that we have the DID, get the document
    let did_doc = match resolve_did_to_document(&did, state.bsky_client.clone()).await {
        Ok(doc) => doc,
        Err(err) => {
            return html! {
                p { "Failed to resolve DID document: " (err) }
            };
        }
    };

    // Get the auth server metadata
    let auth_server_metadata =
        match document_to_auth_server_metadata(&did_doc, state.bsky_client.clone()).await {
            Ok(metadata) => metadata,
            Err(err) => {
                return html! {
                    p { "Failed to get auth server metadata: " (err) }
                };
            }
        };

    html! {
      p { "DID Document: " (Debug(did_doc)) }
      p { "Auth Server Metadata: " (Debug(auth_server_metadata)) }

      // Add a button to start the OAuth flow with this DID
      form action="/oauth/bsky/authorize" method="get" {
        input type="hidden" name="did" value=(did.to_string()) {}
        input type="hidden" name="state" value="from_login_page" {}

        button type="submit" { "Start OAuth Login with " (did.to_string()) }
      }

      p { "Note: Using client_id: " (state.client_id()) }
      p { "Callback URI: " (state.redirect_uri()) }
    }
}

/// Logout route - clears authentication cookies and redirects to home
async fn logout(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    // End the session
    let _ = crate::auth::end_session(&state.db, &cookies).await;

    // Also clear the old legacy cookie if it exists
    if let Some(_cookie) = cookies.get(bsky::AUTH_DID_COOKIE) {
        let mut remove_cookie = Cookie::new(bsky::AUTH_DID_COOKIE, "");
        remove_cookie.set_path("/");
        remove_cookie.set_max_age(time::Duration::seconds(-1));
        remove_cookie.set_http_only(true);
        remove_cookie.set_secure(true);

        cookies.add(remove_cookie);
    }

    // Redirect to home page
    axum::response::Redirect::to("/")
}
