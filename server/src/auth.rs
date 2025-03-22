use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use color_eyre::eyre::eyre;
use time::Duration;
use tower_cookies::{Cookie, Cookies};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    state::AppState,
    user::{Session, User},
};

/// Cookie name for storing the session ID
pub const SESSION_COOKIE_NAME: &str = "pfp_session";

/// Default session duration in days
pub const DEFAULT_SESSION_DURATION_DAYS: i64 = 30;

/// Extract the current user from the request if authenticated
#[derive(Debug, Clone)]
pub struct AuthUser(pub User);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookies = match Cookies::from_request_parts(parts, state).await {
            Ok(cookies) => cookies,
            Err(_) => {
                error!("Failed to extract cookies from request");
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        // Check if we have a session cookie
        let session_id = match get_session_id_from_cookie(&cookies) {
            Some(id) => id,
            None => {
                info!("No session cookie found, redirecting to login");
                return Err(Redirect::to("/login").into_response());
            }
        };

        // Validate the session
        let session = match validate_session(&state.db, session_id).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                info!("Session {} is invalid or expired", session_id);
                return Err(Redirect::to("/login").into_response());
            }
            Err(err) => {
                error!("Error validating session {}: {:?}", session_id, err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        // Get the user for this session
        let user = match session.get_user(&state.db).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                error!("No user found for session {}", session_id);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
            Err(err) => {
                error!("Error getting user for session {}: {:?}", session_id, err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        Ok(AuthUser(user))
    }
}

/// Extract an authenticated admin user from the request
/// Requires both authentication and admin privileges
#[derive(Debug, Clone)]
pub struct AdminUser(pub User);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // First, extract regular authenticated user
        let auth_user = match AuthUser::from_request_parts(parts, state).await {
            Ok(user) => user,
            Err(rejection) => return Err(rejection),
        };

        // Check if user has admin privileges
        if !auth_user.0.is_admin {
            error!(
                "User {} attempted to access admin area without admin privileges",
                auth_user.0.user_id
            );
            return Err(StatusCode::FORBIDDEN.into_response());
        }

        Ok(AdminUser(auth_user.0))
    }
}

/// Extract the optional user from the request if authenticated
#[derive(Debug, Clone)]
pub struct OptionalUser {
    pub user: Option<User>,
}

#[async_trait]
impl FromRequestParts<AppState> for OptionalUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookies = match Cookies::from_request_parts(parts, state).await {
            Ok(cookies) => cookies,
            Err(_) => {
                error!("Failed to extract cookies from request");
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        // Check if we have a session cookie
        let session_id = match get_session_id_from_cookie(&cookies) {
            Some(id) => id,
            None => {
                // No cookie, return None for user
                return Ok(OptionalUser { user: None });
            }
        };

        // Validate the session
        let session = match validate_session(&state.db, session_id).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                // Invalid session, return None for user
                return Ok(OptionalUser { user: None });
            }
            Err(err) => {
                error!("Error validating session {}: {:?}", session_id, err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        // Get the user for this session
        match session.get_user(&state.db).await {
            Ok(Some(user)) => Ok(OptionalUser { user: Some(user) }),
            Ok(None) => Ok(OptionalUser { user: None }),
            Err(err) => {
                error!("Error getting user for session {}: {:?}", session_id, err);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        }
    }
}

/// Get the session ID from the cookie
pub fn get_session_id_from_cookie(cookies: &Cookies) -> Option<Uuid> {
    cookies
        .get(SESSION_COOKIE_NAME)
        .and_then(|cookie| cookie.value().parse::<Uuid>().ok())
}

/// Validate a session
pub async fn validate_session(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> cja::Result<Option<Session>> {
    let session = Session::get_by_id(pool, session_id).await?;

    if let Some(ref session) = session {
        if session.is_expired() {
            info!("Session {} is expired", session_id);
            return Ok(None);
        }

        if !session.is_active {
            info!("Session {} is inactive", session_id);
            return Ok(None);
        }
    }

    Ok(session)
}

/// Creates a session cookie for the given session ID
fn create_session_cookie(session_id: Uuid, duration_days: i64) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, session_id.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(std::env::var("PROTO").ok() == Some("https".to_owned()));
    cookie.set_max_age(Duration::days(duration_days));
    cookie
}

/// Create a new session for a user and set a cookie
pub async fn create_session_and_set_cookie(
    pool: &sqlx::PgPool,
    cookies: &Cookies,
    user_id: Uuid,
    user_agent: Option<String>,
    ip_address: Option<String>,
    primary_token_id: Option<Uuid>,
) -> cja::Result<Session> {
    let duration_days = DEFAULT_SESSION_DURATION_DAYS;

    // Create a new session
    let session = Session::create(
        pool,
        user_id,
        user_agent,
        ip_address,
        duration_days,
        primary_token_id,
    )
    .await?;

    // Set a secure cookie with the session ID
    let cookie = create_session_cookie(session.session_id, duration_days);
    cookies.add(cookie);

    info!(
        "Created new session {} for user {}",
        session.session_id, user_id
    );
    Ok(session)
}

/// Clear the session cookie and invalidate the session in the database
pub async fn end_session(pool: &sqlx::PgPool, cookies: &Cookies) -> cja::Result<()> {
    if let Some(session_id) = get_session_id_from_cookie(cookies) {
        if let Ok(Some(mut session)) = Session::get_by_id(pool, session_id).await {
            session
                .invalidate(pool)
                .await
                .map_err(|e| eyre!("Failed to invalidate session {}: {}", session_id, e))?;

            info!("Session {} invalidated", session_id);
        }
    }

    // Remove the cookie by setting it to expire immediately
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, "");
    cookie.set_path("/");
    cookie.set_max_age(Duration::seconds(-1));
    cookie.set_http_only(true);
    cookie.set_secure(std::env::var("PROTO").ok() == Some("https".to_owned()));

    cookies.add(cookie);
    info!("Session cookie removed");

    Ok(())
}

// Function removed - not used in codebase
