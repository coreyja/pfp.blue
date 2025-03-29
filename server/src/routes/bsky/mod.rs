//! Bluesky OAuth and API integration routes
//! This module contains all routes for Bluesky integration, account management,
//! and profile functionality.

mod auth;
mod blobs;
mod callback;
mod client_metadata;
mod profile;
mod tokens;
mod utils;

// Re-export everything
pub use auth::*;
pub use blobs::*;
pub use callback::*;
pub use client_metadata::*;
pub use profile::*;
pub use tokens::*;
pub use utils::*;

/// Cookie name for storing the user's DID
pub const AUTH_DID_COOKIE: &str = "pfp_auth_did";
