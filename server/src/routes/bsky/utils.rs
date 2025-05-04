use axum::response::IntoResponse;
use cja::server::cookies::CookieJar;
use color_eyre::eyre::eyre;
use maud::html;
use uuid::Uuid;

use crate::{
    components::{
        layout::Page,
        ui::{
            badge::{Badge, BadgeColor},
            button::{Button, ButtonVariant, IconPosition},
            heading::Heading,
        },
    },
    errors::{ServerError, ServerResult},
    oauth::OAuthSession,
    state::AppState,
};

/// Helper function to handle OAuth error responses
pub fn handle_oauth_error(
    error: &str,
    error_description: Option<String>,
    client_id: &str,
    redirect_uri: &str,
) -> Page {
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
}

/// Helper function to handle missing code error
pub fn handle_missing_code_error(
    state_param: Option<&str>,
    client_id: &str,
    redirect_uri: &str,
) -> Page {
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
                        .icon("fa-solid fa-sign-in-alt", IconPosition::Left))

                    (Button::new("Return to Home")
                        .variant(ButtonVariant::Secondary)
                        .href("/")
                        .icon("fa-solid fa-home", IconPosition::Left))
                }
            }
        }
    };

    // Use the Page struct to wrap the content
    Page::new(
        "Authentication Error - pfp.blue".to_string(),
        Box::new(content),
    )
}
