use atrium_api::types::string::Did;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use cja::jobs::Job;
use serde::Deserialize;
use std::time::SystemTime;
use tracing::{error, info};

use crate::{oauth, state::AppState, traits::IsExpired as _};

#[derive(Deserialize)]
pub struct GetTokenParams {
    /// The DID to get a token for
    pub did: String,
}

#[derive(Deserialize)]
pub struct RevokeTokenParams {
    pub did: String,
}
