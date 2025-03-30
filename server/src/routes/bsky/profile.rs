use axum::{extract::State, http::StatusCode, response::IntoResponse};
use cja::jobs::Job;
use maud::html;
use sqlx::Row;
use tower_cookies::Cookies;
use tracing::error;

use crate::{
    oauth::{self, OAuthTokenSet},
    state::AppState,
};

/// Profile page that requires authentication
pub async fn profile(
    State(state): State<AppState>,
    cookies: Cookies,
    crate::auth::AuthUser(user): crate::auth::AuthUser,
) -> impl IntoResponse {
    // Get all tokens for this user
    let tokens = match oauth::db::get_tokens_for_user(&state, user.user_id).await {
        Ok(tokens) => tokens,
        Err(err) => {
            error!("Failed to retrieve tokens for user: {:?}", err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to retrieve tokens".to_string(),
            )
                .into_response();
        }
    };

    // Start background jobs to update display names for all tokens
    // This ensures we have the latest display name data when showing the profile
    for token in &tokens {
        if let Err(err) = crate::jobs::UpdateProfileInfoJob::from_token(token)
            .enqueue(state.clone(), "profile_route".to_string())
            .await
        {
            error!(
                "Failed to enqueue display name update job for DID {}: {:?}",
                token.did, err
            );
        }
    }

    if tokens.is_empty() {
        use crate::components::{
            form::{Form, InputField},
            layout::Page,
            profile::FeatureCard,
            ui::{
                button::{Button, ButtonVariant, IconPosition},
                heading::Heading,
                icon::Icon,
            },
        };
        use maud::Render;

        let form_content = html! {
            (InputField::new("did")
                .placeholder("Enter Bluesky handle or DID")
                .icon(Icon::user())
                .required(true))

            (Button::primary("Link Bluesky Account")
                .icon(Icon::link().into_string(), IconPosition::Left)
                .button_type("submit")
                .full_width(true))
        };

        let content = html! {
            div class="max-w-3xl mx-auto bg-white rounded-2xl shadow-xl overflow-hidden text-center p-8" {
                // App logo
                div class="mb-6 flex justify-center" {
                    (Icon::app_logo())
                }

                (Heading::h1("Welcome to Your Profile!")
                    .with_classes("text-center"))
                p class="text-gray-600 mb-8 text-center" {
                    "You don't have any Bluesky accounts linked yet. Let's get started!"
                }

                // Auth form in a feature card style
                div class="mb-8" {
                    (Form::new("/oauth/bsky/authorize", "get", form_content)
                        .extra_classes("bg-gradient-to-r from-indigo-50 to-blue-50 rounded-xl p-6 border border-dashed border-indigo-200"))
                }

                // Features section with cards
                (Heading::h3("Why link your Bluesky account?"))

                div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8" {
                    (FeatureCard::new(
                        "Profile Management",
                        "Manage your Bluesky profile with ease, including custom profile pictures",
                        "⚙️",
                        crate::components::profile::feature_card::FeatureCardColor::Blue
                    ))

                    (FeatureCard::new(
                        "Multiple Accounts",
                        "Link and manage multiple Bluesky accounts in one place",
                        "👥",
                        crate::components::profile::feature_card::FeatureCardColor::Indigo
                    ))

                    (FeatureCard::new(
                        "Authentication",
                        "Seamless authentication with your Bluesky identity",
                        "🔐",
                        crate::components::profile::feature_card::FeatureCardColor::Purple
                    ))
                }

                // Footer links
                div class="mt-8 pt-4 border-t border-gray-200 flex justify-center gap-4" {
                    (Button::new("Back to Home")
                        .variant(ButtonVariant::Link)
                        .href("/")
                        .icon(Icon::home().into_string(), IconPosition::Left))

                    span class="text-gray-300 self-center" { "|" }

                    (Button::new("Try Different Login")
                        .variant(ButtonVariant::Link)
                        .href("/login")
                        .icon(Icon::login().into_string(), IconPosition::Left))
                }
            }
        };

        return Page {
            title: "Your Profile - pfp.blue".to_string(),
            content: Box::new(content),
        }
        .render()
        .into_response();
    }

    // Get session to check for a set primary token
    let session_id = match crate::auth::get_session_id_from_cookie(&cookies) {
        Some(id) => id,
        None => {
            error!("No valid session found");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Session not found").into_response();
        }
    };

    let session = match crate::auth::validate_session(&state.db, session_id).await {
        Ok(Some(s)) => s,
        _ => {
            error!("Session validation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid session").into_response();
        }
    };

    // Use primary token from session if available, otherwise use the first token
    let primary_token = if let Ok(Some(token)) = session.get_primary_token(&state.db).await {
        token
    } else if !tokens.is_empty() {
        tokens[0].clone()
    } else {
        error!("No tokens available for this user");
        return (StatusCode::BAD_REQUEST, "No Bluesky accounts linked").into_response();
    };

    // Check if the primary token is expired and try to refresh it
    if primary_token.is_expired() {
        // Use our consolidated function to get a valid token
        match oauth::get_valid_token_by_did(&primary_token.did, &state).await {
            Ok(new_token) => {
                // Refresh all tokens
                let tokens = match oauth::db::get_tokens_for_user(&state, user.user_id).await {
                    Ok(tokens) => tokens,
                    Err(_) => vec![new_token.clone()],
                };

                // Display the profile with the refreshed token and all tokens
                return display_profile_multi(&state, new_token, tokens)
                    .await
                    .into_response();
            }
            Err(err) => {
                error!("Failed to refresh token: {:?}", err);
                // Token refresh failed, but we still show the profile with expired token
                // so the user can see other linked accounts
            }
        }
    }

    // Display profile with all tokens
    display_profile_multi(&state, primary_token, tokens)
        .await
        .into_response()
}

/// Display profile information with multiple linked accounts
async fn display_profile_multi(
    state: &AppState,
    primary_token: OAuthTokenSet,
    all_tokens: Vec<OAuthTokenSet>,
) -> maud::Markup {
    use crate::components::{
        form::{Form, InputField, ToggleSwitch},
        layout::Page,
        profile::AccountCard,
        ui::{
            badge::{Badge, BadgeColor},
            button::{Button, ButtonSize, IconPosition},
            heading::Heading,
            icon::Icon,
            nav_buttons::{NavButton, NavButtonIcon, NavButtons},
        },
    };
    use maud::Render;

    // Queue a job to update the handle in the background
    if let Err(err) = crate::jobs::UpdateProfileInfoJob::from_token(&primary_token)
        .enqueue(state.clone(), "display_profile_multi".to_string())
        .await
    {
        error!(
            "Failed to enqueue display name update job for display: {:?}",
            err
        );
    }

    // Fetch profile data with avatar using our API helpers
    let profile_info = match crate::api::get_profile_with_avatar(&primary_token.did, state).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to fetch profile info: {:?}", e);
            // Create default profile info with just the DID
            crate::api::ProfileDataParams {
                display_name: None,
                avatar: None,
                description: None,
                profile_data: None,
            }
        }
    };

    // Extract information for display
    let display_name = profile_info
        .display_name
        .unwrap_or_else(|| primary_token.did.clone());
    // We don't need handle anymore since we use display_name

    // Extract avatar information and encode as base64 if available
    let avatar_blob_cid = profile_info.avatar.as_ref().map(|a| a.cid.clone());

    // Encode avatar as base64 if available
    let avatar_base64 = if let Some(avatar) = &profile_info.avatar {
        avatar.data.as_ref().map(|data| {
            format!(
                "data:{};base64,{}",
                avatar.mime_type,
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data)
            )
        })
    } else {
        None
    };

    // Create profile display content
    let content = html! {
        div class="max-w-3xl mx-auto bg-white rounded-2xl shadow-xl overflow-hidden" {
            // Profile header with fun curves
            div class="relative h-48 bg-gradient-to-r from-blue-500 to-indigo-600" {
                div class="absolute left-0 right-0 bottom-0" {
                    (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 100" class="w-full h-20 fill-white"><path d="M0,64L80,69.3C160,75,320,85,480,80C640,75,800,53,960,42.7C1120,32,1280,32,1360,32L1440,32L1440,100L1360,100C1280,100,1120,100,960,100C800,100,640,100,480,100C320,100,160,100,80,100L0,100Z"></path></svg>"#))
                }
            }

            // Profile content
            div class="px-6 py-8 -mt-20 relative z-10" {
                // Avatar and name section
                div class="flex flex-col md:flex-row items-center mb-8" {
                    // Avatar with playful border
                    div class="relative mb-4 md:mb-0 md:mr-6" {
                        @if let Some(img_src) = &avatar_base64 {
                            div class="rounded-full w-36 h-36 border-4 border-white shadow-lg overflow-hidden bg-white" {
                                img src=(img_src) alt="Profile Picture" class="w-full h-full object-cover" {}
                            }
                        } @else {
                            div class="rounded-full w-36 h-36 border-4 border-white shadow-lg overflow-hidden bg-gradient-to-br from-blue-300 to-indigo-300 flex items-center justify-center text-white font-bold" {
                                "No Image"
                            }
                        }
                        // Fun decorative element
                        div class="absolute -bottom-2 -right-2 w-10 h-10 rounded-full bg-yellow-400 shadow-md border-2 border-white flex items-center justify-center text-white text-xl" {
                            "👋"
                        }
                    }

                    // Profile info
                    div class="text-center md:text-left" {
                        h1 class="text-4xl font-bold mb-3 text-gray-800" title=(primary_token.did) { (display_name) }
                        // We just display the display name now, no need to show handle separately
                        // DID is shown as a tooltip on the display name instead of directly

                        // Playful badges
                        div class="flex flex-wrap justify-center md:justify-start gap-2 mt-2" {
                            (Badge::new("Profile", BadgeColor::Blue).rounded(true))
                            (Badge::new("Bluesky", BadgeColor::Green).rounded(true))
                            (Badge::new("pfp.blue", BadgeColor::Purple).rounded(true))
                        }
                    }
                }

                // Tabs for different sections
                div class="border-b border-gray-200 mb-6" {
                    div class="flex overflow-x-auto" {
                        button class="px-4 py-2 text-indigo-600 border-b-2 border-indigo-600 font-medium" { "Accounts" }
                        button class="px-4 py-2 text-gray-500 hover:text-indigo-600" { "Activity" }
                        button class="px-4 py-2 text-gray-500 hover:text-indigo-600" { "Settings" }
                    }
                }

                // Authentication status section removed for production - only show user-facing info

                // Linked accounts section using AccountCard component
                div class="mb-8" {
                    (Heading::h3("Linked Bluesky Accounts"))

                    div class="space-y-3" {
                        @for token in &all_tokens {
                            (AccountCard::new(&token.did, token.expires_at)
                                .handle(token.display_name.as_deref().unwrap_or(""))
                                .is_primary(token.did == primary_token.did))
                        }
                    }

                    // Add new account form using Form, InputField and Button components
                    div class="mt-6 bg-gradient-to-r from-indigo-50 to-blue-50 rounded-xl p-5 border border-dashed border-indigo-200" {
                        (Form::new(
                            "/oauth/bsky/authorize",
                            "get",
                            html! {
                                div class="flex flex-col sm:flex-row gap-2 items-center" {
                                    div class="w-full sm:flex-grow" {
                                        (InputField::new("did")
                                            .placeholder("Enter Bluesky handle or DID")
                                            .icon(Icon::user()))
                                    }

                                    (Button::primary("Link Account")
                                        .button_type("submit")
                                        .icon(Icon::plus().into_string(), IconPosition::Left))
                                }
                            }
                        ).extra_classes("m-0"))
                    }
                }

                // Raw profile data section removed for production

                // Profile Picture Progress feature
                div class="mb-8" {
                    (Heading::h3("Profile Picture Progress"))
                    div class="bg-indigo-50 rounded-xl p-5 border border-indigo-200" {
                        p class="text-gray-700 mb-4" {
                            "This feature automatically updates your profile picture to show progress from your display name. "
                            "Use a fraction (e.g. 3/10) or percentage (e.g. 30%) in your display name, and we'll visualize it!"
                        }

                        // Get profile progress settings for this token
                        @let progress_settings = match sqlx::query(
                            r#"
                            SELECT p.* FROM profile_picture_progress p
                            JOIN oauth_tokens t ON p.token_id = t.id
                            WHERE t.did = $1
                            "#
                        ).bind(&primary_token.did)
                          .fetch_optional(&state.db)
                          .await {
                            Ok(Some(row)) => {
                                let enabled: bool = row.get("enabled");
                                let original_blob_cid: Option<String> = row.get("original_blob_cid");
                                (enabled, original_blob_cid)
                            },
                            _ => (false, None),
                        };

                        // Toggle switch for enabling/disabling using our ToggleSwitch component
                        form action="/profile_progress/toggle" method="post" class="mb-4" {
                            input type="hidden" name="token_id" value=(primary_token.did) {}

                            (ToggleSwitch::new(
                                "enabled",
                                "Enable Progress Visualization",
                                progress_settings.0
                            ).description("Automatically update your profile picture based on progress in your display name"))

                            div class="mt-3 flex justify-end" {
                                (Button::primary("Save")
                                    .button_type("submit")
                                    .size(ButtonSize::Small))
                            }
                        }

                        // Original profile picture selection
                        form action="/profile_progress/set_original" method="post" class="p-3 bg-white rounded-lg shadow-sm" {
                            p class="font-medium text-gray-900 mb-2" { "Original Profile Picture" }
                            p class="text-sm text-gray-500 mb-4" { "Select the profile picture to use as the base for progress visualization" }

                            input type="hidden" name="token_id" value=(primary_token.did) {}

                            @if progress_settings.1.is_some() {
                                div class="mb-4 flex items-center" {
                                    p class="text-sm text-gray-600" { "You have set an original profile picture" }
                                }
                            }

                            @if let Some(img_src) = &avatar_base64 {
                                div class="flex items-center space-x-4" {
                                    // Display current profile picture
                                    div class="w-16 h-16 rounded-full overflow-hidden bg-white" {
                                        img src=(img_src) alt="Current Profile Picture" class="w-full h-full object-cover" {}
                                    }

                                    // Use current button
                                    @if let Some(cid) = avatar_blob_cid.clone() {
                                        input type="hidden" name="blob_cid" value=(cid) {}
                                        (Button::primary("Use Current Profile Picture")
                                            .button_type("submit")
                                            .size(ButtonSize::Small))
                                    }
                                }
                            }
                        }

                        // Show how to format display name
                        div class="mt-4 p-3 bg-white rounded-lg shadow-sm" {
                            p class="font-medium text-gray-900 mb-2" { "How to format your display name" }
                            div class="space-y-2 text-sm text-gray-600" {
                                p { "Your current display name: "
                                    strong { (display_name) }
                                }
                                p { "To show progress, add one of these patterns to your display name:" }
                                ul class="list-disc list-inside ml-2 space-y-1" {
                                    li { "Fraction: " code class="bg-gray-100 px-1" { "My Name 3/10" } " — Shows 30% progress" }
                                    li { "Percentage: " code class="bg-gray-100 px-1" { "My Name 30%" } " — Shows 30% progress" }
                                    li { "Decimal: " code class="bg-gray-100 px-1" { "My Name 30.5%" } " — Shows 30.5% progress" }
                                }
                            }
                        }
                    }
                }

                // Action buttons footer using our new component
                (NavButtons::new()
                    .add_button(NavButton::new("Home", "/")
                        .with_icon(NavButtonIcon::Home))
                    .add_button(NavButton::new("Logout", "/logout")
                        .with_icon(NavButtonIcon::Logout))
                    .add_button(NavButton::new("Switch User", "/login")
                        .with_icon(NavButtonIcon::Login)))
            }
        }
    };

    // Use the Page struct to wrap the content
    Page {
        title: format!("{} - Bluesky Profile - pfp.blue", display_name),
        content: Box::new(content),
    }
    .render()
}
