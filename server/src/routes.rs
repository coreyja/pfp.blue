use crate::{
    auth::{AdminUser, AuthUser, OptionalUser},
    components::layout::Page,
    errors::{ServerResult, WithRedirect},
    profile_progress::ProfilePictureProgress,
    state::AppState,
};
use axum::{
    extract::{Form, State},
    response::Response,
};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use cja::jobs::Job as _;
use color_eyre::eyre::{eyre, WrapErr};
use serde::Deserialize;
use std::collections::HashMap;
use tower_cookies::{Cookie, Cookies};
use tracing::{error, info};
use uuid::Uuid;

pub mod bsky;

/// Build the application router with all routes
pub fn routes(app_state: AppState) -> axum::Router {
    axum::Router::new()
        // Public pages
        .route("/", get(root_page))
        .route("/login", get(login_page))
        .route("/logout", get(logout))
        .route("/about", get(about_page))
        .route("/privacy", get(privacy_policy_page))
        // Authenticated pages
        .route("/me", get(bsky::profile))
        // Profile Picture Progress routes
        .route("/profile_progress/toggle", post(toggle_profile_progress))
        // Bluesky OAuth routes
        .route("/oauth/bsky/metadata.json", get(bsky::client_metadata))
        .route("/oauth/bsky/authorize", get(bsky::authorize))
        .route("/oauth/bsky/callback", get(bsky::callback))
        .route("/oauth/bsky/token", get(bsky::get_token))
        .route("/oauth/bsky/revoke", get(bsky::revoke_token))
        .route("/oauth/bsky/set-primary", get(bsky::set_primary_account))
        // Admin routes
        .route("/_", get(admin_panel))
        .route("/_/job/enqueue", post(admin_enqueue_job))
        .route("/_/job/run", post(admin_run_job))
        // Static files route
        .route(
            "/static/*path",
            get(crate::static_assets::serve_static_file),
        )
        // Add trace layer for debugging
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app_state)
}

/// Root page handler - displays the homepage
async fn root_page(optional_user: OptionalUser, State(state): State<AppState>) -> Page {
    use crate::components::{
        layout::Card,
        profile::feature_card::{FeatureCard, FeatureCardColor},
        ui::{
            button::{Button, ButtonSize, IconPosition},
            heading::Heading,
            icon::Icon,
        },
    };
    use maud::Render;

    // Get display name and personalized content if user is logged in
    let (greeting, buttons, card_width) = match &optional_user.user {
        Some(user) => {
            // Try to get the user's primary token to display their handle/name
            let display_name = match sqlx::query!(
                r#"
                SELECT t.display_name, t.did
                FROM sessions s
                JOIN oauth_tokens t ON s.primary_token_id = t.uuid_id
                WHERE s.user_id = $1
                LIMIT 1
                "#,
                user.user_id
            )
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some(row)) => {
                    // Use display name if available, otherwise show DID
                    row.display_name
                        .unwrap_or_else(|| format!("@{}", row.did))
                        .replace("@", "")
                }
                _ => "there".to_string(),
            };

            // Personalized greeting with display name
            let greeting_text = format!("Welcome back, @{}!", display_name);

            // Action buttons for logged in users
            let action_buttons = maud::html! {
                (Button::primary("Go to My Profile")
                    .href("/me")
                    .icon("fa-solid fa-user", IconPosition::Left)
                    .full_width(true)
                    .size(ButtonSize::Large)
                    .render())
            };

            // Wider card for logged in users with more content
            (greeting_text, action_buttons, "max-w-lg")
        }
        None => {
            // Welcome message for non-logged in users
            let greeting_text = "Welcome to pfp.blue!".to_string();

            // Login buttons for non-logged in users
            let action_buttons = maud::html! {
                div class="space-y-4" {
                    (Button::primary("Sign in with Bluesky")
                        .href("/login")
                        .icon("fa-solid fa-sign-in-alt", IconPosition::Left)
                        .full_width(true)
                        .size(ButtonSize::Large)
                        .render())

                    p class="text-sm text-gray-500" {
                        "New to Bluesky? "
                        a href="https://bsky.app" target="_blank" class="text-indigo-600 hover:text-indigo-800 underline" {
                            "Visit Bluesky"
                        }
                    }
                }
            };

            (greeting_text, action_buttons, "max-w-md")
        }
    };

    let content = maud::html! {
        div class="text-center px-4 sm:px-8 py-6 sm:py-8" {
            // Banner for the app
            div class="mb-4 sm:mb-6 flex justify-center" {
                (crate::static_assets::banner_img("w-64 sm:w-80 md:w-96 mx-auto"))
            }

            // Display personalized greeting
            h2 class="text-xl sm:text-2xl font-semibold text-indigo-700 mt-2" { (greeting) }
            p class="text-base sm:text-lg text-gray-600 mb-6 sm:mb-8" { "Your Bluesky Profile Manager" }

            // Action buttons
            div class="space-y-4" {
                (buttons)
            }

            // Connect & Follow section
            div class="mt-8 sm:mt-10 flex flex-wrap justify-center gap-3" {
                a href="https://github.com/coreyja/pfp.blue" target="_blank"
                  class="inline-flex items-center px-4 sm:px-5 py-2 sm:py-2.5 text-sm font-medium rounded-md bg-purple-100 text-purple-700 hover:bg-purple-200 transition-colors cursor-pointer" {
                    // GitHub icon
                    i class="fa-brands fa-github h-5 w-5 mr-2" {}
                    "Star on GitHub"
                }

                a href="https://bsky.app/profile/pfp.blue" target="_blank"
                  class="inline-flex items-center px-4 sm:px-5 py-2 sm:py-2.5 text-sm font-medium rounded-md bg-blue-100 text-blue-700 hover:bg-blue-200 transition-colors cursor-pointer" {
                    // Bluesky icon
                    i class="fa-solid fa-comment-dots h-5 w-5 mr-2" {}
                    "Follow @pfp.blue"
                }
            }

            // Features section
            div class="mt-10 sm:mt-12" {
                (Heading::h2("Features").render())

                div class="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4 mt-4" {
                    (FeatureCard::new(
                        "Profile Progress",
                        "Show your progress visually in your profile picture with automatic updates",
                        "📊",
                        FeatureCardColor::Blue
                    ).render())

                    (FeatureCard::new(
                        "Multiple Accounts",
                        "Easily manage and switch between all your Bluesky accounts",
                        "🔄",
                        FeatureCardColor::Indigo
                    ).render())

                    (FeatureCard::new(
                        "Secure Access",
                        "Industry-standard OAuth for safe and private authorization",
                        "🔐",
                        FeatureCardColor::Purple
                    ).render())

                    (FeatureCard::new(
                        "Free to Use",
                        "All features are completely free and open to everyone",
                        "✨",
                        FeatureCardColor::Pink
                    ).render())
                }
            }

            // Coming soon section - improved for mobile
            div class="mt-8 sm:mt-10 p-4 sm:p-5 bg-gradient-to-r from-purple-50 to-pink-50 rounded-lg sm:rounded-xl border border-purple-100 shadow-sm" {
                h3 class="text-base sm:text-lg font-medium text-purple-800" { "Coming Soon" }
                p class="text-xs sm:text-sm text-gray-700 mt-1 sm:mt-2" { "More profile customization options and enhanced features!" }
            }
        }
    };

    Page::new(
        "pfp.blue - Bluesky Profile Manager".to_string(),
        Box::new(Card::new(content).with_max_width(card_width)),
    )
}

/// Login page handler - displays the login form
async fn login_page(State(state): State<AppState>) -> impl IntoResponse {
    use crate::components::{
        form::{Form, InputField},
        layout::{Card, ContentSection, CurvedHeader, Page},
        ui::{
            button::{Button, ButtonSize, IconPosition},
            heading::Heading,
            icon::Icon,
        },
    };
    use maud::Render;

    let login_form = maud::html! {
        // Title and intro
        (Heading::h1("Welcome to pfp.blue")
            .with_classes("text-center mt-4")
            .render())
        p class="text-gray-600 mb-6 text-center" { "Log in to manage your Bluesky profile" }

        // Bluesky OAuth login
        div class="bg-gradient-to-r from-indigo-50 to-purple-50 rounded-xl p-6 border border-dashed border-indigo-200" {
            // Form header with icon
            div class="flex items-center gap-2 mb-4" {
                div class="w-10 h-10 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600" {
                    "🚀"
                }
                (Heading::h2("Login with Bluesky")
                    .with_color("text-indigo-800")
                    .render())
            }

            // Description
            p class="text-gray-600 mb-6" {
                "Enter your Bluesky handle (e.g., @username.bsky.social) or DID (e.g., did:plc:...) to connect your account."
            }

            (Form::new("/oauth/bsky/authorize", "get", maud::html! {
                (InputField::new("did")
                    .placeholder("Enter your handle or DID")
                    .icon("fa-solid fa-user")
                    .required(true)
                    .render())

                (InputField::new("state")
                    .value("from_login_page")
                    .hidden(true)
                    .render())

                (Button::primary("Connect with Bluesky")
                    .full_width(true)
                    .size(ButtonSize::Large)
                    .button_type("submit")
                    .icon("fa-solid fa-link", IconPosition::Left)
                    .render())
            }).render())
        }

        // Footer links
        div class="mt-6 pt-4 border-t border-gray-200 text-center" {
            div class="flex justify-center gap-4" {
                a href="/" class="text-indigo-600 hover:text-indigo-800 transition-colors duration-200" { "Back to Home" }
            }
        }
    };

    // Debug info
    let debug_info = maud::html! {
        details class="mt-8 mx-auto bg-white/70 rounded-lg shadow-sm p-4 text-sm text-gray-600" {
            summary class="font-medium cursor-pointer" { "Debug Information" }
            div class="mt-2 space-y-1" {
                p { "Client ID: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.client_id()) } }
                p { "Redirect URI: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.redirect_uri()) } }
                p { "Domain: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.domain) } }
                p { "Protocol: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.protocol) } }
            }
        }
    };

    let card_content = maud::html! {
        // Header with curved bottom
        (CurvedHeader::new("h-32").render())

        // Login content
        (ContentSection::new(login_form).render())
    };

    let content = maud::html! {
        (Card::new(card_content).with_max_width("max-w-md").render())
        (debug_info)
    };

    Page::new("Login - pfp.blue".to_string(), Box::new(content)).render()
}

/// Parameters for toggling profile picture progress
#[derive(Deserialize)]
struct ToggleProfileProgressParams {
    token_id: String, // This is the DID string, not a UUID
    enabled: Option<String>,
}

/// Handler for toggling profile picture progress
async fn toggle_profile_progress(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Form(params): Form<ToggleProfileProgressParams>,
) -> ServerResult<Response, Redirect> {
    // Validate token ownership and get token ID
    let token_id = validate_token_ownership(&state, &params.token_id, user.user_id)
        .await
        .wrap_err("Failed to validate token ownership")
        .with_redirect(Redirect::to("/me"))?;

    // Check if we're enabling the feature
    // When the form is submitted with enabled=true we're enabling
    // When it's submitted without the enabled parameter we're disabling
    let is_enabling = params.enabled.is_some();

    // Get or create the profile progress settings
    let mut settings = ProfilePictureProgress::get_or_create(&state.db, token_id, is_enabling)
        .await
        .wrap_err("Failed to get or create profile progress settings")
        .with_redirect(Redirect::to("/me"))?;

    // Update the enabled status
    settings
        .update_enabled(&state.db, is_enabling)
        .await
        .wrap_err("Failed to update profile progress settings")
        .with_redirect(Redirect::to("/me"))?;

    info!(
        "Updated profile progress settings for token {}: enabled={}",
        token_id, is_enabling
    );

    // If we're enabling the feature, automatically save the current profile picture as the base
    if is_enabling {
        // Get the token information
        let row = sqlx::query!(
            r#"
            SELECT * FROM oauth_tokens
            WHERE id = $1
            "#,
            token_id
        )
        .fetch_optional(&state.db)
        .await
        .wrap_err("Database error when fetching token")
        .with_redirect(Redirect::to("/me"))?;

        // Check if the token was found
        if let Some(row) = row {
            // Get token data
            let token = crate::oauth::OAuthTokenSet {
                did: row.did.clone(),
                display_name: row.display_name.clone(),
                handle: row.handle.clone(),
                access_token: row.access_token.clone(),
                refresh_token: row.refresh_token.clone(),
                token_type: row.token_type.clone(),
                scope: row.scope.clone(),
                expires_at: row.expires_at as u64,
                dpop_jkt: row.dpop_jkt.clone(),
                user_id: Some(row.user_id),
            };

            // Fetch profile info to get the current avatar blob CID
            if let Ok(profile_info) = crate::api::get_profile_with_avatar(&token.did, &state).await
            {
                if let Some(avatar) = profile_info.avatar {
                    // Get the blob data
                    if let Ok(blob_data) =
                        crate::routes::bsky::fetch_blob_by_cid(&token.did, &avatar.cid, &state)
                            .await
                    {
                        // Upload to get a proper blob object
                        if let Ok(blob_object) = crate::jobs::helpers::upload_image_to_bluesky(
                            &state, &token, &blob_data,
                        )
                        .await
                        {
                            // Save the blob object to our custom PDS collection
                            if let Err(e) = crate::jobs::helpers::save_original_profile_picture(
                                &state,
                                &token,
                                blob_object,
                            )
                            .await
                            {
                                error!(
                                    "Failed to save original profile picture to PDS for DID {}: {:?}",
                                    token.did, e
                                );
                                // We continue even if this fails - the feature will still work just without an original picture
                            } else {
                                info!(
                                    "Automatically saved original profile picture to PDS collection for DID {}",
                                    token.did
                                );
                            }
                        }
                    }
                }
            }

            // Enqueue a job to update the profile picture
            let job = crate::jobs::UpdateProfilePictureProgressJob::new(token_id);
            if let Err(e) = job
                .enqueue(state.clone(), "enabled_profile_progress".to_string())
                .await
            {
                error!("Failed to enqueue profile picture update job: {:?}", e);
                // Even if job enqueueing fails, we continue - it's not critical
            } else {
                info!("Enqueued profile picture update job for token {}", token_id);
            }
        }
    }

    // Redirect back to profile page
    Ok(Redirect::to("/me").into_response())
}

// Previous set_original_profile_picture handler removed - functionality is now part of toggle_profile_progress

/// Helper function to validate token ownership and return token ID
async fn validate_token_ownership(state: &AppState, did: &str, user_id: Uuid) -> cja::Result<Uuid> {
    let token_result = sqlx::query!(
        r#"
        SELECT id FROM oauth_tokens
        WHERE did = $1 AND user_id = $2
        "#,
        did,
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .wrap_err_with(|| {
        format!(
            "Database error when checking token ownership for DID: {}",
            did
        )
    })?;

    match token_result {
        Some(row) => Ok(row.id),
        None => {
            error!("Attempted to access token not belonging to user: {}", did);
            Err(eyre!(
                "Token {} not found or not owned by user {}",
                did,
                user_id
            ))
        }
    }
}

/// Logout route - clears authentication cookies and redirects to home
async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
) -> ServerResult<impl IntoResponse, StatusCode> {
    // End the session
    crate::auth::end_session(&state.db, &cookies)
        .await
        .wrap_err("Failed to end user session")?;

    // Also clear the old legacy cookie if it exists
    if let Some(_cookie) = cookies.get(bsky::AUTH_DID_COOKIE) {
        let mut remove_cookie = Cookie::new(bsky::AUTH_DID_COOKIE, "");
        remove_cookie.set_path("/");
        remove_cookie.set_max_age(time::Duration::seconds(-1));
        remove_cookie.set_http_only(true);
        remove_cookie.set_secure(std::env::var("PROTO").ok() == Some("https".to_owned()));

        cookies.add(remove_cookie);
        info!("Removed legacy auth cookie");
    }

    // Redirect to home page
    info!("User logged out successfully");
    Ok(Redirect::to("/"))
}

/// About page handler
async fn about_page(_optional_user: OptionalUser, State(_state): State<AppState>) -> Page {
    use crate::components::{
        layout::{Card, ContentSection, CurvedHeader},
        ui::heading::Heading,
    };
    use maud::Render;

    let content = maud::html! {
        // Header with curved bottom
        (CurvedHeader::new("h-32").render())

        // Main content
        (ContentSection::new(maud::html! {
            (Heading::h1("About pfp.blue")
                .with_color("text-indigo-700")
                .render())

            // About content
            div class="mt-6 space-y-6 text-gray-700" {
                p class="leading-relaxed" {
                    "pfp.blue was created by Corey Alexander, a software developer who goes by "
                    strong { "coreyja" } " online."
                }

                p class="leading-relaxed" {
                    "I built pfp.blue to explore the Bluesky APIs and ecosystem, creating a useful tool that helps people visualize their progress right in their profile pictures."
                }

                div class="mt-8 bg-blue-50 rounded-lg p-4 border border-blue-100" {
                    h3 class="text-blue-800 font-medium mb-2" { "Connect with Corey" }

                    ul class="space-y-2" {
                        li class="flex items-center" {
                            // Bluesky icon
                            i class="fa-solid fa-comment-dots h-5 w-5 mr-2 text-blue-600" {}
                            "Bluesky: "
                            a href="https://bsky.app/profile/coreyja.com" target="_blank" class="text-blue-600 hover:underline" { "@coreyja.com" }
                        }

                        li class="flex items-center" {
                            // Web icon
                            i class="fa-solid fa-globe h-5 w-5 mr-2 text-blue-600" {}
                            "Website: "
                            a href="https://coreyja.com" target="_blank" class="text-blue-600 hover:underline" { "coreyja.com" }
                        }

                        li class="flex items-center" {
                            // GitHub icon
                            i class="fa-brands fa-github h-5 w-5 mr-2 text-blue-600" {}
                            "GitHub: "
                            a href="https://github.com/coreyja" target="_blank" class="text-blue-600 hover:underline" { "coreyja" }
                        }
                    }
                }
            }

        }).render())
    };

    Page::new(
        "About - pfp.blue".to_string(),
        Box::new(Card::new(content).with_max_width("max-w-3xl")),
    )
}

/// Privacy policy page handler
async fn privacy_policy_page(_optional_user: OptionalUser, State(_state): State<AppState>) -> Page {
    use crate::components::{
        layout::{Card, ContentSection, CurvedHeader},
        ui::heading::Heading,
    };
    use maud::Render;

    let content = maud::html! {
        // Header with curved bottom
        (CurvedHeader::new("h-32").render())

        // Main content
        (ContentSection::new(maud::html! {
            (Heading::h1("Privacy Policy")
                .with_color("text-indigo-700")
                .render())

            // Privacy policy content
            div class="mt-6 space-y-6 text-gray-700" {
                div class="p-4 bg-gray-50 rounded-md border border-gray-200 mb-8" {
                    p class="text-sm italic" { "Last Updated: April 1, 2025" }
                }

                p class="leading-relaxed" {
                    "At pfp.blue, we take your privacy seriously. This page outlines what information we collect and how we use it."
                }

                h3 class="text-lg font-medium text-indigo-700 mt-6" { "Information We Collect" }
                p class="leading-relaxed" {
                    "We only collect the minimum information required to provide our service:"
                }
                ul class="list-disc ml-6 space-y-1 mt-2" {
                    li { "Your Bluesky handle and DID" }
                    li { "OAuth tokens to authenticate with Bluesky" }
                    li { "Your original profile picture (stored on Bluesky's servers, not ours)" }
                }

                h3 class="text-lg font-medium text-indigo-700 mt-6" { "How We Use Your Information" }
                p class="leading-relaxed" {
                    "We use the collected information only to provide the profile picture progress visualization service. We do not share your data with third parties."
                }

                h3 class="text-lg font-medium text-indigo-700 mt-6" { "Contact" }
                p class="leading-relaxed" {
                    "If you have any questions about this privacy policy, please contact us on Bluesky: "
                    a href="https://bsky.app/profile/pfp.blue" target="_blank" class="text-blue-600 hover:underline" { "@pfp.blue" }
                }
            }

        }).render())
    };

    Page::new(
        "Privacy Policy - pfp.blue".to_string(),
        Box::new(Card::new(content).with_max_width("max-w-3xl")),
    )
}

/// Admin panel page - shows available jobs and provides a UI to run them
async fn admin_panel(
    AdminUser(user): AdminUser,
    State(_state): State<AppState>,
) -> impl IntoResponse {
    use crate::components::{layout::Page, ui::heading::Heading};
    use maud::{html, Render};

    let available_jobs = crate::jobs::get_available_jobs();

    let jobs_html = html! {
        div class="space-y-6" {
            @for job_name in available_jobs {
                div class="bg-white rounded-lg shadow-sm p-4 border border-gray-200" {
                    h3 class="text-lg font-medium text-gray-800 mb-2" { (job_name) }

                    // Parameters form
                    form action="/_/job/enqueue" method="post" class="mb-4" {
                        input type="hidden" name="job_name" value=(job_name);

                        // Display parameter inputs based on job type
                        @let params = crate::jobs::get_job_params(job_name);
                        @if !params.is_empty() {
                            div class="space-y-3 mb-4" {
                                @for (param_name, description, required) in params {
                                    div class="flex flex-col" {
                                        label for=(format!("{}-{}", job_name, param_name)) class="text-sm font-medium text-gray-700 mb-1" {
                                            (param_name)
                                            @if required {
                                                span class="text-red-500" { " *" }
                                            }
                                        }
                                        input
                                            type="text"
                                            id=(format!("{}-{}", job_name, param_name))
                                            name=(param_name)
                                            class="border rounded-md px-3 py-2 text-sm"
                                            placeholder=(description)
                                            required=(required);
                                    }
                                }
                            }
                        } @else {
                            p class="text-sm text-gray-500 italic mb-4" { "This job does not require any parameters." }
                        }

                        // Submit buttons
                        div class="flex space-x-2" {
                            button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm" { "Enqueue Job" }
                            button type="submit" formaction="/_/job/run" class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded text-sm" { "Run Now" }
                        }
                    }
                }
            }
        }
    };

    let content = html! {
        div class="p-6 max-w-4xl mx-auto" {
            (Heading::h1("Admin Panel").render())

            p class="text-gray-600 mb-6" {
                "Hello, Administrator! "
                @if let Some(username) = &user.username {
                    "(" (username) ")"
                }
            }

            (Heading::h2("Available Jobs").render())
            (jobs_html)
        }
    };

    Page::new("Admin Panel - pfp.blue".to_string(), Box::new(content)).render()
}

/// Input parameters for job operations
#[derive(Debug, Deserialize)]
struct JobParams {
    job_name: String,
    #[serde(flatten)]
    args: HashMap<String, String>,
}

/// Handler for enqueueing a job
async fn admin_enqueue_job(
    AdminUser(_): AdminUser,
    State(state): State<AppState>,
    Form(params): Form<JobParams>,
) -> impl IntoResponse {
    use crate::components::layout::Page;
    use maud::{html, Render};

    let mut args = params.args.clone();
    // Remove the job_name key if it somehow got into the args
    args.remove("job_name");

    // Create the job from the provided parameters
    let job_result = crate::jobs::create_job_from_name_and_args(&params.job_name, args);

    let job = match job_result {
        Ok(job) => job,
        Err(error) => {
            error!("Failed to create job {}: {}", params.job_name, error);
            let content = html! {
                div class="p-6 max-w-4xl mx-auto" {
                    h1 class="text-2xl font-bold text-red-600 mb-4" { "Error Creating Job" }
                    p class="text-gray-700 mb-4" { "Failed to create job: " (error) }
                    a href="/_" class="text-blue-600 hover:underline" { "Back to Admin Panel" }
                }
            };

            return Page { show_header: false,
                title: "Job Error - pfp.blue".to_string(),
                content: Box::new(content),
            }
            .render();
        }
    };

    // Enqueue the job
    let result = job.enqueue(state).await;

    match result {
        Ok(_) => {
            info!("Successfully enqueued job {}", job.name());

            let content = html! {
                div class="p-6 max-w-4xl mx-auto" {
                    h1 class="text-2xl font-bold text-green-600 mb-4" { "Job Enqueued Successfully" }
                    p class="text-gray-700 mb-4" { "Job " b { (job.name()) } " has been enqueued for background processing." }
                    a href="/_" class="text-blue-600 hover:underline" { "Back to Admin Panel" }
                }
            };

            Page::new(
                "Job Enqueued - pfp.blue".to_string(),
                Box::new(content)
            )
            .render()
        }
        Err(err) => {
            error!("Failed to enqueue job {}: {:?}", job.name(), err);

            let content = html! {
                div class="p-6 max-w-4xl mx-auto" {
                    h1 class="text-2xl font-bold text-red-600 mb-4" { "Error Enqueueing Job" }
                    p class="text-gray-700 mb-4" { "Failed to enqueue job: " (err.to_string()) }
                    a href="/_" class="text-blue-600 hover:underline" { "Back to Admin Panel" }
                }
            };

            Page { show_header: false,
                title: "Job Error - pfp.blue".to_string(),
                content: Box::new(content),
            }
            .render()
        }
    }
}

/// Handler for running a job immediately
async fn admin_run_job(
    AdminUser(_): AdminUser,
    State(state): State<AppState>,
    Form(params): Form<JobParams>,
) -> impl IntoResponse {
    use crate::components::layout::Page;
    use maud::{html, Render};

    let mut args = params.args.clone();
    // Remove the job_name key if it somehow got into the args
    args.remove("job_name");

    // Create the job from the provided parameters
    let job_result = crate::jobs::create_job_from_name_and_args(&params.job_name, args);

    let job = match job_result {
        Ok(job) => job,
        Err(error) => {
            error!("Failed to create job {}: {}", params.job_name, error);
            let content = html! {
                div class="p-6 max-w-4xl mx-auto" {
                    h1 class="text-2xl font-bold text-red-600 mb-4" { "Error Creating Job" }
                    p class="text-gray-700 mb-4" { "Failed to create job: " (error) }
                    a href="/_" class="text-blue-600 hover:underline" { "Back to Admin Panel" }
                }
            };

            return Page { show_header: false,
                title: "Job Error - pfp.blue".to_string(),
                content: Box::new(content),
            }
            .render();
        }
    };

    // Run the job immediately
    let result = job.run(state.clone()).await;

    match result {
        Ok(_) => {
            info!("Successfully ran job {}", job.name());

            let content = html! {
                div class="p-6 max-w-4xl mx-auto" {
                    h1 class="text-2xl font-bold text-green-600 mb-4" { "Job Completed Successfully" }
                    p class="text-gray-700 mb-4" { "Job " b { (job.name()) } " has been executed successfully." }
                    a href="/_" class="text-blue-600 hover:underline" { "Back to Admin Panel" }
                }
            };

            Page::new(
                "Job Completed - pfp.blue".to_string(),
                Box::new(content)
            )
            .render()
        }
        Err(err) => {
            error!("Failed to run job {}: {:?}", job.name(), err);

            let content = html! {
                div class="p-6 max-w-4xl mx-auto" {
                    h1 class="text-2xl font-bold text-red-600 mb-4" { "Error Running Job" }
                    p class="text-gray-700 mb-4" { "Failed to run job: " (err.to_string()) }
                    a href="/_" class="text-blue-600 hover:underline" { "Back to Admin Panel" }
                }
            };

            Page { show_header: false,
                title: "Job Error - pfp.blue".to_string(),
                content: Box::new(content),
            }
            .render()
        }
    }
}
