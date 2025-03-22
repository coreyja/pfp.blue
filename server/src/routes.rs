use crate::{
    auth::{AdminUser, AuthUser, OptionalUser},
    profile_progress::ProfilePictureProgress,
    state::AppState,
};
use axum::extract::{Form, State};
use axum::{
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use cja::jobs::Job as _;
use color_eyre::eyre::eyre;
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
        // Authenticated pages
        .route("/me", get(bsky::profile))
        // Profile Picture Progress routes
        .route("/profile_progress/toggle", post(toggle_profile_progress))
        .route(
            "/profile_progress/set_original",
            post(set_original_profile_picture),
        )
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
        // Add trace layer for debugging
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app_state)
}

/// Root page handler - displays the homepage
async fn root_page(optional_user: OptionalUser) -> impl IntoResponse {
    use crate::components::{
        layout::{Card, Page},
        profile::feature_card::{FeatureCard, FeatureCardColor},
        ui::{
            button::{Button, ButtonSize},
            heading::Heading,
            icon::Icon,
        },
    };
    use maud::Render;

    // Use OptionalUser to customize the page based on login status
    let greeting = match &optional_user.user {
        Some(user) => format!("Welcome back! User ID: {}", user.user_id),
        None => "Welcome to pfp.blue!".to_string(),
    };

    let content = maud::html! {
        div class="text-center p-8" {
            // Logo/icon for the app
            div class="mb-6 flex justify-center" {
                (Icon::app_logo())
            }

            // Display personalized greeting
            h2 class="text-xl font-semibold text-indigo-700 mt-2" { (greeting) }

            (Heading::h1("pfp.blue").render())
            p class="text-lg text-gray-600 mb-8" { "Your Bluesky Profile Manager" }

            // Action buttons
            div class="space-y-4" {
                (Button::primary("View Your Profile")
                    .href("/me")
                    .full_width(true)
                    .size(ButtonSize::Large)
                    .render())

                (Button::secondary("Login")
                    .href("/login")
                    .full_width(true)
                    .size(ButtonSize::Large)
                    .render())
            }

            // Features section
            div class="mt-12" {
                (Heading::h2("Features").render())

                div class="grid grid-cols-1 md:grid-cols-2 gap-4" {
                    (FeatureCard::new(
                        "Secure Login",
                        "Authenticate securely with your Bluesky account",
                        "🔐",
                        FeatureCardColor::Blue
                    ).render())

                    (FeatureCard::new(
                        "Profile Management",
                        "Manage your Bluesky profile with ease",
                        "👤",
                        FeatureCardColor::Indigo
                    ).render())

                    (FeatureCard::new(
                        "Multiple Accounts",
                        "Link and manage multiple Bluesky accounts",
                        "🔄",
                        FeatureCardColor::Purple
                    ).render())

                    (FeatureCard::new(
                        "Easy Setup",
                        "Get started quickly with a simple setup process",
                        "🚀",
                        FeatureCardColor::Pink
                    ).render())
                }
            }
        }
    };

    Page {
        title: "pfp.blue - Bluesky Profile Manager".to_string(),
        content: Box::new(Card::new(content).with_max_width("max-w-md")),
    }
    .render()
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
                    .icon(Icon::user().into_string())
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
                    .icon(Icon::link().into_string(), IconPosition::Left)
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

    Page {
        title: "Login - pfp.blue".to_string(),
        content: Box::new(content),
    }
    .render()
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
) -> impl IntoResponse {
    // Validate token ownership and get token ID
    let token_id = match validate_token_ownership(&state, &params.token_id, user.user_id).await {
        Ok(id) => id,
        Err(e) => {
            error!("Token ownership validation failed: {}", e);
            return Redirect::to("/me").into_response();
        }
    };

    // Get or create the profile progress settings
    let result =
        ProfilePictureProgress::get_or_create(&state.db, token_id, params.enabled.is_some(), None)
            .await;

    match result {
        Ok(mut settings) => {
            // Update the enabled status
            if let Err(err) = settings
                .update_enabled(&state.db, params.enabled.is_some())
                .await
            {
                error!("Failed to update profile progress settings: {:?}", err);
            } else {
                info!(
                    "Updated profile progress settings for token {}: enabled={}",
                    token_id,
                    params.enabled.is_some()
                );
            }
        }
        Err(err) => {
            error!("Failed to get/create profile progress settings: {:?}", err);
        }
    }

    // Redirect back to profile page
    Redirect::to("/me").into_response()
}

/// Parameters for setting original profile picture
#[derive(Deserialize)]
struct SetOriginalProfilePictureParams {
    token_id: String, // This is the DID string, not a UUID
    blob_cid: String,
}

/// Handler for setting original profile picture
async fn set_original_profile_picture(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Form(params): Form<SetOriginalProfilePictureParams>,
) -> impl IntoResponse {
    // Validate token ownership and get token ID
    let token_id = match validate_token_ownership(&state, &params.token_id, user.user_id).await {
        Ok(id) => id,
        Err(e) => {
            error!("Token ownership validation failed: {}", e);
            return Redirect::to("/me").into_response();
        }
    };

    // Get or create the profile progress settings
    let result = ProfilePictureProgress::get_or_create(
        &state.db,
        token_id,
        true, // Enable when setting an original profile picture
        Some(params.blob_cid.clone()),
    )
    .await;

    match result {
        Ok(mut settings) => {
            // Update the original blob CID
            if let Err(err) = settings
                .update_original_blob_cid(&state.db, Some(params.blob_cid.clone()))
                .await
            {
                error!("Failed to update original blob CID: {:?}", err);
            } else {
                info!(
                    "Updated original blob CID for token {}: {}",
                    token_id, params.blob_cid
                );

                // Enqueue a job to update the profile picture
                enqueue_profile_picture_update_job(&state, token_id).await;
            }
        }
        Err(err) => {
            error!("Failed to get/create profile progress settings: {:?}", err);
        }
    }

    // Redirect back to profile page
    Redirect::to("/me").into_response()
}

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
    .map_err(|e| {
        error!("Database error when checking token ownership: {:?}", e);
        eyre!("Database error: {}", e)
    })?;

    match token_result {
        Some(row) => Ok(row.id),
        None => {
            error!("Attempted to access token not belonging to user: {}", did);
            Err(eyre!("Token not found or not owned by user"))
        }
    }
}

/// Helper function to enqueue a profile picture update job
async fn enqueue_profile_picture_update_job(state: &AppState, token_id: Uuid) {
    let job = crate::jobs::UpdateProfilePictureProgressJob::new(token_id);
    if let Err(e) = job
        .enqueue(state.clone(), "enabled_profile_progress".to_string())
        .await
    {
        error!("Failed to enqueue profile picture update job: {:?}", e);
    } else {
        info!("Enqueued profile picture update job for token {}", token_id);
    }
}

/// Logout route - clears authentication cookies and redirects to home
async fn logout(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    // End the session
    if let Err(e) = crate::auth::end_session(&state.db, &cookies).await {
        error!("Error ending session: {:?}", e);
    }

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
    Redirect::to("/")
}

/// Admin panel page - shows available jobs and provides a UI to run them
async fn admin_panel(AdminUser(user): AdminUser, State(_state): State<AppState>) -> impl IntoResponse {
    use crate::components::{
        layout::Page,
        ui::heading::Heading,
    };
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

    Page {
        title: "Admin Panel - pfp.blue".to_string(),
        content: Box::new(content),
    }
    .render()
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
            
            return Page {
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
            
            Page {
                title: "Job Enqueued - pfp.blue".to_string(),
                content: Box::new(content),
            }
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
            
            Page {
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
            
            return Page {
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
            
            Page {
                title: "Job Completed - pfp.blue".to_string(),
                content: Box::new(content),
            }
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
            
            Page {
                title: "Job Error - pfp.blue".to_string(),
                content: Box::new(content),
            }
            .render()
        }
    }
}
