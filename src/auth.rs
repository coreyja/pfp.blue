use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use tower_cookies::{Cookie, Cookies};
use tracing::{error, info};
use uuid::Uuid;
use time;

use crate::{
    state::AppState,
    user::{Session, User},
};

/// Cookie name for storing the session ID
pub const SESSION_COOKIE_NAME: &str = "pfp_session";

// The AuthUser extractor below handles auth validation, so no middleware is needed

/// Extract the current user from the request if authenticated
#[derive(Debug, Clone)]
pub struct AuthUser(pub User);

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let cookies = match Cookies::from_request_parts(parts, state).await {
            Ok(cookies) => cookies,
            Err(_) => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        // Check if we have a session cookie
        let session_id = match get_session_id_from_cookie(&cookies) {
            Some(id) => id,
            None => {
                return Err(Redirect::to("/login").into_response());
            }
        };

        // Validate the session
        let session = match validate_session(&state.db, session_id).await {
            Ok(Some(session)) => session,
            _ => {
                return Err(Redirect::to("/login").into_response());
            }
        };

        // Get the user for this session
        let user = match session.get_user(&state.db).await {
            Ok(Some(user)) => user,
            _ => {
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        Ok(AuthUser(user))
    }
}

// We don't need a separate AuthSession extractor since AuthUser already validates the session
// and provides access to the user, which is what we typically need

/// Get the session ID from the cookie
fn get_session_id_from_cookie(cookies: &Cookies) -> Option<Uuid> {
    cookies.get(SESSION_COOKIE_NAME)
        .and_then(|cookie| cookie.value().parse::<Uuid>().ok())
}

/// Validate a session
async fn validate_session(pool: &sqlx::PgPool, session_id: Uuid) -> cja::Result<Option<Session>> {
    let session = Session::get_by_id(pool, session_id).await?;
    
    if let Some(ref session) = session {
        if session.is_expired() || !session.is_active {
            return Ok(None);
        }
    }
    
    Ok(session)
}

/// Create a new session for a user and set a cookie
pub async fn create_session_and_set_cookie(
    pool: &sqlx::PgPool,
    cookies: &Cookies,
    user_id: Uuid,
    user_agent: Option<String>,
    ip_address: Option<String>,
) -> cja::Result<Session> {
    // Create a new session
    let session = Session::create(pool, user_id, user_agent, ip_address, 30).await?;
    
    // Set a secure cookie with the session ID
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, session.session_id.to_string());
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_max_age(time::Duration::days(30));
    
    cookies.add(cookie);
    
    Ok(session)
}

/// Clear the session cookie and invalidate the session in the database
pub async fn end_session(pool: &sqlx::PgPool, cookies: &Cookies) -> cja::Result<()> {
    if let Some(session_id) = get_session_id_from_cookie(cookies) {
        if let Ok(Some(mut session)) = Session::get_by_id(pool, session_id).await {
            session.invalidate(pool).await?;
        }
    }
    
    // Remove the cookie by setting it to expire immediately
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, "");
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::seconds(-1));
    cookie.set_http_only(true);
    cookie.set_secure(true);
    
    cookies.add(cookie);
    
    Ok(())
}