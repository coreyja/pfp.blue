use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse as _, Response},
};
use reqwest::StatusCode;
use tracing::error;

pub use tower_cookies::Cookie;

use crate::state::AppState;

pub struct CookieJar {
    cookies: tower_cookies::Cookies,
    state: AppState,
}

#[async_trait::async_trait]
impl FromRequestParts<AppState> for CookieJar {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookies = match tower_cookies::Cookies::from_request_parts(parts, state).await {
            Ok(cookies) => cookies,
            Err(_) => {
                error!("Failed to extract cookies from request");
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        Ok(CookieJar {
            cookies,
            state: state.clone(),
        })
    }
}

impl CookieJar {
    /// Add a new private cookie
    pub fn add(&self, cookie: tower_cookies::Cookie<'static>) {
        let private = self.cookies.private(&self.state.cookie_key);
        private.add(cookie);
    }

    /// Get a private cookie by name
    pub fn get(&self, name: &str) -> Option<tower_cookies::Cookie<'static>> {
        let private = self.cookies.private(&self.state.cookie_key);
        private.get(name)
    }

    /// Removes the `cookie` from the jar.
    pub fn remove(&self, cookie: tower_cookies::Cookie<'static>) {
        let private = self.cookies.private(&self.state.cookie_key);
        private.remove(cookie);
    }
}
