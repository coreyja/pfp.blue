use atrium_oauth::CallbackParams;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Redirect, Response},
};
use cja::{app_state::AppState as _, server::cookies::CookieJar};
use sea_orm::{ActiveModelTrait as _, ActiveValue};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    auth::OptionalUser,
    errors::ServerResult,
    oauth::{self, OAuthTokenSet},
    state::AppState,
};

use super::utils::extract_dpop_nonce_from_error;

/// Helper function to exchange code for token
async fn exchange_auth_code_for_token(
    oauth_config: &crate::state::BlueskyOAuthConfig,
    session_id: Uuid,
    session: &oauth::OAuthSession,
    code: &str,
    client_id: &str,
    redirect_uri: &str,
    app_state: &AppState,
) -> Result<oauth::TokenResponse, (StatusCode, String)> {
    let code_verifier = session.code_verifier.as_deref();
    let mut attempts = 0;
    let mut last_error = None;
    let mut token_response = None;

    // Try up to 2 times - once with the stored nonce and once with a new nonce if needed
    while attempts < 2 && token_response.is_none() {
        match oauth::exchange_code_for_token(
            oauth_config,
            &session.token_endpoint,
            client_id,
            code,
            redirect_uri,
            code_verifier,
            session.dpop_nonce.as_deref(), // Use the stored nonce if available
        )
        .await
        {
            Ok(response) => {
                token_response = Some(response);
            }
            Err(err) => {
                last_error = Some(err.to_string());

                // Check if the error contains a DPoP nonce error
                if let Some(error_msg) = last_error.as_ref() {
                    if error_msg.contains("use_dpop_nonce") || error_msg.contains("nonce mismatch")
                    {
                        // Try to extract the nonce from the error message
                        if let Some(nonce) = extract_dpop_nonce_from_error(error_msg) {
                            // Save the new nonce in the database for this session
                            if let Err(e) =
                                oauth::db::update_session_nonce(app_state, session_id, &nonce).await
                            {
                                error!("Failed to update session nonce: {:?}", e);
                            } else {
                                // Continue to retry with the new nonce
                                attempts += 1;
                                continue;
                            }
                        }
                    }
                }

                // If we couldn't extract a nonce or it's not a nonce error, break
                break;
            }
        }

        attempts += 1;
    }

    match token_response {
        Some(token) => Ok(token),
        None => {
            let error_msg = last_error.unwrap_or_else(|| "Unknown error".to_string());
            error!("Token exchange failed: {:?}", error_msg);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Failed to exchange authorization code for token: {:?}",
                    error_msg
                ),
            ))
        }
    }
}

/// Helper function to create a user session if needed
async fn ensure_user_session(
    cookies: &CookieJar<AppState>,
    state: &AppState,
    user_id: uuid::Uuid,
    token_set: &OAuthTokenSet,
) -> Result<(), (StatusCode, String)> {
    // Check if we already have a session
    let have_session = if let Some(session_id) = crate::auth::get_session_id_from_cookie(cookies) {
        matches!(
            crate::auth::validate_session(state, session_id).await,
            Ok(Some(_))
        )
    } else {
        false
    };

    // Only create a new session if we don't already have one
    if !have_session {
        // Get the token id to use as primary token
        let token_id = match sqlx::query!(
            r#"
            SELECT uuid_id FROM oauth_tokens WHERE did = $1
            "#,
            &token_set.did
        )
        .fetch_optional(state.db())
        .await
        {
            Ok(Some(row)) => Some(row.uuid_id),
            _ => None,
        };

        if let Err(err) =
            crate::auth::create_session_and_set_cookie(state, cookies, user_id, token_id).await
        {
            error!("Failed to create session: {:?}", err);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session".to_string(),
            ));
        }
    }

    Ok(())
}

pub async fn callback(
    State(state): State<AppState>,
    cookies: CookieJar<AppState>,
    Query(params): Query<CallbackParams>,
    OptionalUser { user, session }: OptionalUser,
) -> ServerResult<Redirect, Response> {
    // // Use the consistent helpers
    // let client_id = state.client_id();
    // let redirect_uri = state.redirect_uri();

    // // Log all parameters for debugging
    // info!(
    //     "Callback received: code: {:?}, state: {:?}, error: {:?}, error_description: {:?}",
    //     params.code, params.state, params.error, params.error_description
    // );

    // // Also log cookie info
    // if let Some(session_cookie) = cookies.get("bsky_session_id") {
    //     info!("Found session cookie: {}", session_cookie.value());
    // } else {
    //     info!("No session cookie found");
    // }

    // // If we have an error, display it
    // if let Some(error) = params.error {
    //     return Err(ServerError(
    //         eyre!("Oauth Error"),
    //         handle_oauth_error(&error, params.error_description, &client_id, &redirect_uri)
    //             .into_response(),
    //     ));
    // }

    // // Make sure we have a code
    // let code = match params.code {
    //     Some(code) => code,
    //     None => {
    //         return Err(ServerError(
    //             eyre!("No code parameter in callback"),
    //             handle_missing_code_error(params.state.as_deref(), &client_id, &redirect_uri)
    //                 .into_response(),
    //         ));
    //     }
    // };

    info!("Received code: {}, state: {:?}", params.code, params.state);

    let (oauth_session, _) = state.atrium_oauth.callback(params).await.unwrap();

    use atrium_api::agent::SessionManager;
    info!("OAuth session DID: {:?}", oauth_session.did().await);

    // TODO: If there is not a user, create one and create a session attached to it
    let user = if let Some(user) = user {
        user
    } else {
        let user = crate::orm::users::ActiveModel {
            is_admin: ActiveValue::Set(false),
            ..Default::default()
        };
        user.insert(&state.orm).await.unwrap()
    };

    Ok(Redirect::to("/me"))

    // // Get the session ID and data
    // let (session_id, session) =
    //     utils::get_session_id_and_data(params.state.as_deref(), &cookies, &state).await?;

    // // Exchange the authorization code for an access token
    // let token_response = match exchange_auth_code_for_token(
    //     &state.bsky_oauth,
    //     session_id,
    //     &session,
    //     &code,
    //     &client_id,
    //     &redirect_uri,
    //     &state,
    // )
    // .await
    // {
    //     Ok(token) => token,
    //     Err((status, message)) => {
    //         return Err(ServerError(
    //             eyre!(
    //                 "Failed to exchange authorization code for token: {:?}",
    //                 message
    //             ),
    //             (status, message).into_response(),
    //         ));
    //     }
    // };

    // // Check if there's an existing user session
    // let current_user_id = check_existing_user_session(&cookies, &state).await;

    // // Create a token set with JWK thumbprint and user_id if we have one
    // let mut token_set = match OAuthTokenSet::from_token_response_with_jwk(
    //     &token_response,
    //     session.did.clone(),
    //     &state.bsky_oauth.public_key,
    // ) {
    //     Ok(token) => token,
    //     Err(err) => {
    //         error!("Failed to create token set with JWK: {:?}", err);
    //         // Fallback to standard token creation without JWK calculation
    //         OAuthTokenSet::from_token_response(token_response, session.did.clone())
    //     }
    // };

    // // If we found a user session, associate this token with that user
    // if let Some(user_id) = current_user_id {
    //     token_set.user_id = Some(user_id);
    // }

    // // Store the token in the database with encryption
    // if let Err(err) = oauth::db::store_token(&state, &token_set).await {
    //     error!("Failed to store token: {:?}", err);
    //     return Err(ServerError(
    //         eyre!("Failed to store access token"),
    //         (
    //             StatusCode::INTERNAL_SERVER_ERROR,
    //             "Failed to store access token".to_string(),
    //         )
    //             .into_response(),
    //     ));
    // }

    // // Schedule a background job to update the display name
    // if let Err(err) = crate::jobs::UpdateProfileInfoJob::from_token(&token_set)
    //     .enqueue(state.clone(), "callback".to_string())
    //     .await
    // {
    //     // Log the error but continue - not fatal
    //     error!("Failed to enqueue display name update job: {:?}", err);
    // } else {
    //     info!("Queued display name update job for DID: {}", session.did);
    // }

    // info!("Authentication successful for DID: {}", session.did);

    // // Get or create a user ID for this token
    // let user_id = match get_or_create_user_id_for_token(&token_set, &session.did, &state.db).await {
    //     Ok(id) => id,
    //     Err((status, message)) => {
    //         return Err(ServerError(
    //             eyre!("Failed to get or create user ID: {:?}", message),
    //             (status, message).into_response(),
    //         ));
    //     }
    // };

    // // Ensure we have a user session
    // if let Err((status, message)) = ensure_user_session(&cookies, &state, user_id, &token_set).await
    // {
    //     return Err(ServerError(
    //         eyre!("Failed to ensure user session: {:?}", message),
    //         (status, message).into_response(),
    //     ));
    // }

    // // Redirect to the profile page
    // info!("Setting auth cookies and redirecting to /me");
    // Ok(Redirect::to("/me"))
}
