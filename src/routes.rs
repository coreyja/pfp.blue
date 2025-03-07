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
        .route("/oauth/bsky/set-primary", get(bsky::set_primary_account))
        // Add trace layer for debugging
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app_state)
}

async fn root() -> impl IntoResponse {
    maud::html! {
        // Add Tailwind CSS from CDN
        script src="https://unpkg.com/@tailwindcss/browser@4" {}

        // Main container with gradient background matching profile page
        div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
            div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden text-center p-8" {
                // Logo/icon for the app
                div class="mb-6 flex justify-center" {
                    (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" class="text-indigo-500"><circle cx="12" cy="8" r="5"></circle><path d="M20 21v-2a7 7 0 0 0-14 0v2"></path><line x1="12" y1="8" x2="12" y2="8"></line><path d="M3 20h18a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1H9L3 12v7a1 1 0 0 0 1 1z"></path></svg>"#))
                }
                
                h1 class="text-4xl font-bold text-gray-800 mb-3" { "pfp.blue" }
                p class="text-lg text-gray-600 mb-8" { "Your Bluesky Profile Manager" }
                
                // Action buttons
                div class="space-y-4" {
                    a href="/me" 
                        class="block w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 px-4 rounded-lg transition-colors duration-200" { 
                        "View Your Profile" 
                    }
                    
                    a href="/login" 
                        class="block w-full bg-white hover:bg-gray-50 text-indigo-600 font-medium py-3 px-4 rounded-lg border border-indigo-300 hover:border-indigo-400 transition-colors duration-200" { 
                        "Login" 
                    }
                }
                
                // Features section
                div class="mt-12" {
                    h2 class="text-xl font-semibold text-gray-800 mb-4" { "Features" }
                    
                    div class="grid grid-cols-1 md:grid-cols-2 gap-4" {
                        div class="bg-blue-50 p-4 rounded-lg text-left" {
                            div class="flex items-center gap-2 mb-2" {
                                div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-blue-600" {
                                    "🔐"
                                }
                                h3 class="font-medium text-blue-800" { "Secure Login" }
                            }
                            p class="text-sm text-gray-600" { "Authenticate securely with your Bluesky account" }
                        }
                        
                        div class="bg-indigo-50 p-4 rounded-lg text-left" {
                            div class="flex items-center gap-2 mb-2" {
                                div class="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600" {
                                    "👤"
                                }
                                h3 class="font-medium text-indigo-800" { "Profile Management" }
                            }
                            p class="text-sm text-gray-600" { "Manage your Bluesky profile with ease" }
                        }
                        
                        div class="bg-purple-50 p-4 rounded-lg text-left" {
                            div class="flex items-center gap-2 mb-2" {
                                div class="w-8 h-8 rounded-full bg-purple-100 flex items-center justify-center text-purple-600" {
                                    "🔄"
                                }
                                h3 class="font-medium text-purple-800" { "Multiple Accounts" }
                            }
                            p class="text-sm text-gray-600" { "Link and manage multiple Bluesky accounts" }
                        }
                        
                        div class="bg-pink-50 p-4 rounded-lg text-left" {
                            div class="flex items-center gap-2 mb-2" {
                                div class="w-8 h-8 rounded-full bg-pink-100 flex items-center justify-center text-pink-600" {
                                    "🚀"
                                }
                                h3 class="font-medium text-pink-800" { "Easy Setup" }
                            }
                            p class="text-sm text-gray-600" { "Get started quickly with a simple setup process" }
                        }
                    }
                }
            }
            
            // Footer credit
            div class="mt-8 text-center text-gray-500 text-sm" {
                p { "© 2025 pfp.blue - Bluesky Profile Management" }
            }
        }
    }
}

async fn login(State(state): State<AppState>) -> impl IntoResponse {
    maud::html! {
        // Add Tailwind CSS from CDN
        script src="https://unpkg.com/@tailwindcss/browser@4" {}

        // Main container with gradient background matching profile page
        div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
            div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden" {
                // Header with fun curve
                div class="relative h-32 bg-gradient-to-r from-blue-500 to-indigo-600" {
                    div class="absolute left-0 right-0 bottom-0" {
                        (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 100" class="w-full h-20 fill-white"><path d="M0,64L80,69.3C160,75,320,85,480,80C640,75,800,53,960,42.7C1120,32,1280,32,1360,32L1440,32L1440,100L1360,100C1280,100,1120,100,960,100C800,100,640,100,480,100C320,100,160,100,80,100L0,100Z"></path></svg>"#))
                    }
                }

                // Login content
                div class="px-8 py-6 pt-0 pb-8" {
                    // Title and intro
                    h1 class="text-3xl font-bold text-gray-800 mb-2 mt-4 text-center" { "Welcome to pfp.blue" }
                    p class="text-gray-600 mb-6 text-center" { "Log in to manage your Bluesky profile" }

                    // Standard login form
                    div class="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl p-6 border border-dashed border-blue-200 mb-6" {
                        // Form header with icon
                        div class="flex items-center gap-2 mb-4" {
                            div class="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center text-blue-600" {
                                "🔑"
                            }
                            h2 class="text-lg font-semibold text-blue-800" { "Standard Login" }
                        }
                        
                        form action="/login" method="post" class="space-y-4" {
                            div class="relative" {
                                div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" {
                                    (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>"#))
                                }
                                input type="text" name="handle_or_did" placeholder="Enter your handle or DID" 
                                    class="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-gray-900" {}
                            }
                            
                            button type="submit" 
                                class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors duration-200" { 
                                "Login" 
                            }
                        }
                    }

                    // Bluesky OAuth login
                    div class="bg-gradient-to-r from-indigo-50 to-purple-50 rounded-xl p-6 border border-dashed border-indigo-200" {
                        // Form header with icon
                        div class="flex items-center gap-2 mb-4" {
                            div class="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600" {
                                "🚀"
                            }
                            h2 class="text-lg font-semibold text-indigo-800" { "Login with Bluesky" }
                        }
                        
                        form action="/oauth/bsky/authorize" method="get" class="space-y-4" {
                            div class="relative" {
                                div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none" {
                                    (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>"#))
                                }
                                input type="text" name="did" placeholder="Enter your handle or DID" 
                                    class="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-gray-900" {}
                                input type="hidden" name="state" value="from_login_page" {}
                            }
                            
                            button type="submit" 
                                class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center" { 
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>"#))
                                "Login with Bluesky" 
                            }
                        }
                    }

                    // Footer links
                    div class="mt-6 pt-4 border-t border-gray-200 text-center" {
                        div class="flex justify-center gap-4" {
                            a href="/" class="text-indigo-600 hover:text-indigo-800 transition-colors duration-200" { "Back to Home" }
                        }
                    }
                }
            }
            
            // Debug info hidden in expandable section
            details class="mt-8 max-w-md mx-auto bg-white/70 rounded-lg shadow-sm p-4 text-sm text-gray-600" {
                summary class="font-medium cursor-pointer" { "Debug Information" }
                div class="mt-2 space-y-1" {
                    p { "Client ID: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.client_id()) } }
                    p { "Redirect URI: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.redirect_uri()) } }
                    p { "Domain: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.domain) } }
                    p { "Protocol: " span class="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded" { (state.protocol) } }
                }
            }
            
            // Footer credit
            div class="mt-8 text-center text-gray-500 text-sm" {
                p { "pfp.blue - Your Bluesky Profile Manager" }
            }
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
    // First, determine if input is a handle or DID and resolve to a DID
    let did = if form.handle_or_did.starts_with("did:") {
        // Input is already a DID
        match Did::new(form.handle_or_did.clone()) {
            Ok(did) => did,
            Err(_) => {
                return html! {
                    // Add Tailwind CSS from CDN
                    script src="https://unpkg.com/@tailwindcss/browser@4" {}
                    
                    div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                        div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden p-8" {
                            div class="bg-red-50 p-4 rounded-lg border border-red-200 mb-6 text-center" {
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="mx-auto h-12 w-12 text-red-400 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>"#))
                                h2 class="text-lg font-semibold text-red-800 mb-2" { "Error" }
                                p class="text-red-700" { "Invalid DID format" }
                            }
                            
                            div class="flex justify-center mt-6" {
                                a href="/login" class="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200" {
                                    "Back to Login"
                                }
                            }
                        }
                    }
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
                            // Add Tailwind CSS from CDN
                            script src="https://unpkg.com/@tailwindcss/browser@4" {}
                            
                            div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                                div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden p-8" {
                                    div class="bg-red-50 p-4 rounded-lg border border-red-200 mb-6 text-center" {
                                        (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="mx-auto h-12 w-12 text-red-400 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>"#))
                                        h2 class="text-lg font-semibold text-red-800 mb-2" { "Error" }
                                        p class="text-red-700" { "Failed to resolve handle to DID: " (err) }
                                    }
                                    
                                    div class="flex justify-center mt-6" {
                                        a href="/login" class="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200" {
                                            "Back to Login"
                                        }
                                    }
                                }
                            }
                        };
                    }
                }
            }
            Err(_) => {
                return html! {
                    // Add Tailwind CSS from CDN
                    script src="https://unpkg.com/@tailwindcss/browser@4" {}
                    
                    div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                        div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden p-8" {
                            div class="bg-red-50 p-4 rounded-lg border border-red-200 mb-6 text-center" {
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="mx-auto h-12 w-12 text-red-400 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>"#))
                                h2 class="text-lg font-semibold text-red-800 mb-2" { "Error" }
                                p class="text-red-700" { "Invalid handle format" }
                            }
                            
                            div class="flex justify-center mt-6" {
                                a href="/login" class="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200" {
                                    "Back to Login"
                                }
                            }
                        }
                    }
                };
            }
        }
    };

    // Now that we have the DID, get the document
    let did_doc = match resolve_did_to_document(&did, state.bsky_client.clone()).await {
        Ok(doc) => doc,
        Err(err) => {
            return html! {
                // Add Tailwind CSS from CDN
                script src="https://unpkg.com/@tailwindcss/browser@4" {}
                
                div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                    div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden p-8" {
                        div class="bg-red-50 p-4 rounded-lg border border-red-200 mb-6 text-center" {
                            (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="mx-auto h-12 w-12 text-red-400 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>"#))
                            h2 class="text-lg font-semibold text-red-800 mb-2" { "Error" }
                            p class="text-red-700" { "Failed to resolve DID document: " (err) }
                        }
                        
                        div class="flex justify-center mt-6" {
                            a href="/login" class="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200" {
                                "Back to Login"
                            }
                        }
                    }
                }
            };
        }
    };

    // Get the auth server metadata
    let auth_server_metadata =
        match document_to_auth_server_metadata(&did_doc, state.bsky_client.clone()).await {
            Ok(metadata) => metadata,
            Err(err) => {
                return html! {
                    // Add Tailwind CSS from CDN
                    script src="https://unpkg.com/@tailwindcss/browser@4" {}
                    
                    div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                        div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden p-8" {
                            div class="bg-red-50 p-4 rounded-lg border border-red-200 mb-6 text-center" {
                                (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="mx-auto h-12 w-12 text-red-400 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>"#))
                                h2 class="text-lg font-semibold text-red-800 mb-2" { "Error" }
                                p class="text-red-700" { "Failed to get auth server metadata: " (err) }
                            }
                            
                            div class="flex justify-center mt-6" {
                                a href="/login" class="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200" {
                                    "Back to Login"
                                }
                            }
                        }
                    }
                };
            }
        };

    html! {
        // Add Tailwind CSS from CDN
        script src="https://unpkg.com/@tailwindcss/browser@4" {}
        
        div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
            div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl overflow-hidden p-8" {
                // Success header
                div class="mb-6 text-center" {
                    div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-100 text-green-600 mb-4" {
                        (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>"#))
                    }
                    h2 class="text-2xl font-bold text-gray-800 mb-2" { "DID Resolved Successfully" }
                    p class="text-gray-600 mb-6" { "We found your Bluesky identity. Continue to authenticate." }
                }
                
                // OAuth button card
                div class="bg-gradient-to-r from-indigo-50 to-purple-50 rounded-xl p-6 border border-dashed border-indigo-200 mb-6" {
                    p class="text-gray-700 mb-4" { "Ready to authenticate with: " }
                    p class="text-indigo-700 font-semibold mb-6 bg-white/60 p-3 rounded-lg text-center break-all" { (did.to_string()) }
                    
                    // Add a button to start the OAuth flow with this DID
                    form action="/oauth/bsky/authorize" method="get" class="mt-4" {
                        input type="hidden" name="did" value=(did.to_string()) {}
                        input type="hidden" name="state" value="from_login_page" {}
                        
                        button type="submit" 
                            class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 px-4 rounded-lg transition-colors duration-200 flex items-center justify-center" { 
                            (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>"#))
                            "Complete Authentication" 
                        }
                    }
                }
                
                // Debug info in expandable section
                details class="bg-white/70 rounded-lg p-4 text-sm text-gray-600 mt-4" {
                    summary class="font-medium cursor-pointer" { "Technical Details" }
                    div class="mt-4 space-y-4 overflow-auto max-h-60 bg-gray-50 p-3 rounded" {
                        div class="space-y-1" {
                            p class="font-semibold" { "Client ID:" }
                            p class="font-mono text-xs bg-white p-2 rounded" { (state.client_id()) }
                        }
                        div class="space-y-1" {
                            p class="font-semibold" { "Callback URI:" }
                            p class="font-mono text-xs bg-white p-2 rounded" { (state.redirect_uri()) }
                        }
                        div class="space-y-1 mt-2" {
                            p class="font-semibold" { "DID Document:" }
                            pre class="whitespace-pre-wrap font-mono text-xs bg-white p-2 rounded" { (Debug(did_doc)) }
                        }
                        div class="space-y-1 mt-2" {
                            p class="font-semibold" { "Auth Server Metadata:" }
                            pre class="whitespace-pre-wrap font-mono text-xs bg-white p-2 rounded" { (Debug(auth_server_metadata)) }
                        }
                    }
                }
                
                // Back button
                div class="mt-6 text-center" {
                    a href="/login" class="text-indigo-600 hover:text-indigo-800 transition-colors duration-200" { "Back to Login" }
                }
            }
        }
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
