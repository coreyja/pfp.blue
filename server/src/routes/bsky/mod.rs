//! Bluesky OAuth and API integration routes
//! This module contains all routes for Bluesky integration, account management,
//! and profile functionality.

mod client_metadata;
mod auth;
mod callback;
mod profile;
mod tokens;
mod blobs;
mod utils;

// Re-export everything
pub use client_metadata::*;
pub use auth::*;
pub use callback::*;
pub use profile::*;
pub use tokens::*;
pub use blobs::*;
pub use utils::*;

/// Cookie name for storing the user's DID
pub const AUTH_DID_COOKIE: &str = "pfp_auth_did";