use axum::response::IntoResponse;
use maud::{html, Render};
use uuid::Uuid;

use crate::{
    components::{
        layout::Page,
        ui::{
            badge::{Badge, BadgeColor},
            button::{Button, ButtonVariant, IconPosition},
            heading::Heading,
            icon::Icon,
        },
    },
    oauth::OAuthSession,
    state::AppState,
};

/// Helper function to handle OAuth error responses
pub fn handle_oauth_error(
    error: &str,
    error_description: Option<String>,
    client_id: &str,
    redirect_uri: &str,
) -> axum::response::Response {
    let error_description =
        error_description.unwrap_or_else(|| "No error description provided".to_string());
    tracing::error!("OAuth error: {} - {}", error, error_description);

    // Create error page content
    let content = html! {
        div class="max-w-lg mx-auto bg-white rounded-2xl shadow-xl overflow-hidden" {
            div class="px-8 py-6" {
                (Heading::h1("Authentication Error"))
                p class="text-red-600 font-medium mb-4" { "There was an error during authentication:" }

                div class="mb-4" {
                    p class="text-gray-700" { "Error: " }
                    (Badge::new(error, BadgeColor::Red).rounded(true))
                }

                div class="mb-6" {
                    p class="text-gray-700" { "Description: " }
                    p class="text-gray-600 italic" { (error_description) }
                }

                details class="mb-6 bg-gray-50 p-3 rounded-lg" {
                    summary class="cursor-pointer font-medium text-gray-700" { "Debug Information" }
                    div class="mt-2 space-y-1 text-sm" {
                        p { "Client ID: " (client_id) }
                        p { "Redirect URI: " (redirect_uri) }
                    }
                }

                div class="flex justify-center mt-4" {
                    (Button::primary("Return to Home").href("/"))
                }
            }
        }
    };

    // Use the Page struct to wrap the content
    Page::new(
        "Authentication Error - pfp.blue".to_string(),
        Box::new(content),
    )
    .render()
    .into_response()
}

/// Helper function to handle missing code error
pub fn handle_missing_code_error(
    state_param: Option<&str>,
    client_id: &str,
    redirect_uri: &str,
) -> axum::response::Response {
    tracing::error!("No code parameter in callback");

    // Create error page content
    let content = html! {
        div class="max-w-lg mx-auto bg-white rounded-2xl shadow-xl overflow-hidden" {
            div class="px-8 py-6" {
                (Heading::h1("Authentication Error"))
                p class="text-red-600 font-medium mb-2" { "There was an error during the authorization process." }
                p class="text-gray-700 mb-6" { "The Bluesky server did not provide an authorization code in the callback." }

                details class="mb-6 bg-gray-50 p-3 rounded-lg" {
                    summary class="cursor-pointer font-medium text-gray-700" { "Debug Information" }
                    div class="mt-2 space-y-1 text-sm" {
                        p { "State parameter: " (state_param.unwrap_or("None")) }
                        p { "Client ID: " (client_id) }
                        p { "Redirect URI: " (redirect_uri) }
                    }
                }

                div class="flex flex-col sm:flex-row justify-center gap-4 mt-6" {
                    (Button::primary("Try Again")
                        .href("/login")
                        .icon(Icon::login().into_string(), IconPosition::Left))

                    (Button::new("Return to Home")
                        .variant(ButtonVariant::Secondary)
                        .href("/")
                        .icon(Icon::home().into_string(), IconPosition::Left))
                }
            }
        }
    };

    // Use the Page struct to wrap the content
    Page::new(
        "Authentication Error - pfp.blue".to_string(),
        Box::new(content),
    )
    .render()
    .into_response()
}

/// Helper function to get session ID from state or cookie
pub async fn get_session_id_and_data(
    state_param: Option<&str>,
    cookies: &tower_cookies::Cookies,
    app_state: &AppState,
) -> Result<(Uuid, OAuthSession), (axum::http::StatusCode, String)> {
    // Get the session ID from the state parameter or the cookie
    let session_id = match state_param
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            cookies
                .get("bsky_session_id")
                .and_then(|c| Uuid::parse_str(c.value()).ok())
        }) {
        Some(id) => id,
        None => {
            tracing::error!("No valid session ID found in state or cookie");
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "No valid session found. Please try authenticating again.".to_string(),
            ));
        }
    };

    // Retrieve session data from the database
    let session = match crate::oauth::db::get_session(app_state, session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            tracing::error!("Session not found: {}", session_id);
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "Session not found. Please try authenticating again.".to_string(),
            ));
        }
        Err(err) => {
            tracing::error!("Failed to retrieve session: {:?}", err);
            return Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve session data".to_string(),
            ));
        }
    };

    // Check if the session is expired
    if session.is_expired() {
        tracing::error!("Session expired: {}", session_id);
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Session expired. Please try authenticating again.".to_string(),
        ));
    }

    Ok((session_id, session))
}

/// Extract DPoP nonce from error message
pub fn extract_dpop_nonce_from_error(error_message: &str) -> Option<String> {
    if let Some(nonce_start) = error_message.find("\"dpop_nonce\":\"") {
        let nonce_substring = &error_message[nonce_start + 14..];
        if let Some(nonce_end) = nonce_substring.find('\"') {
            let new_nonce = &nonce_substring[..nonce_end];
            return Some(new_nonce.to_string());
        }
    }
    None
}

/// Helper function to get the token endpoint for a DID from stored sessions
pub async fn get_token_endpoint_for_did(
    pool: &sqlx::PgPool,
    did: &str,
) -> cja::Result<Option<String>> {
    let row = sqlx::query!(
        r#"
        SELECT token_endpoint FROM oauth_sessions
        WHERE did = $1
        ORDER BY updated_at_utc DESC
        LIMIT 1
        "#,
        did
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.token_endpoint))
}
