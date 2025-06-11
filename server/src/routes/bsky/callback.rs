use atrium_oauth::CallbackParams;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use cja::{jobs::Job, server::cookies::CookieJar};
use color_eyre::eyre::WrapErr;
use sea_orm::{
    ActiveModelTrait as _, ActiveValue, ColumnTrait as _, EntityTrait as _, QueryFilter as _,
};
use tracing::info;

use crate::{
    auth::{create_session_and_set_cookie, OptionalUser},
    errors::{ServerError, ServerResult},
    state::AppState,
};

use crate::orm::prelude::*;

pub async fn callback(
    State(state): State<AppState>,
    cookies: CookieJar<AppState>,
    Query(params): Query<CallbackParams>,
    OptionalUser { user, session: _ }: OptionalUser,
) -> ServerResult<Redirect, Response> {
    info!("Received code: {}, state: {:?}", params.code, params.state);

    let (oauth_session, _) = match state.atrium.oauth.callback(params).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("OAuth callback failed with detailed error: {:#?}", e);
            // Try to get more detailed error information
            tracing::error!("Error display: {}", e);
            tracing::error!("Error debug: {:?}", e);
            return Err(ServerError(
                color_eyre::eyre::eyre!("OAuth callback failed: {}", e),
                (Redirect::to("/login?error=oauth_callback_failed")).into_response(),
            ));
        }
    };

    use atrium_api::agent::SessionManager;
    info!("OAuth session DID: {:?}", oauth_session.did().await);

    // Get or create a user
    let user = if let Some(user) = user {
        user
    } else {
        let user = crate::orm::users::ActiveModel {
            is_admin: ActiveValue::Set(false),
            ..Default::default()
        };
        user.insert(&state.orm)
            .await
            .wrap_err("Failed to create user")
            .map_err(|e| {
                tracing::error!("User creation failed: {:?}", e);
                ServerError(e, (Redirect::to("/login?error=user_creation_failed")).into_response())
            })?
    };

    let did = oauth_session
        .did()
        .await
        .ok_or_else(|| {
            tracing::error!("OAuth session missing DID");
            ServerError(
                color_eyre::eyre::eyre!("OAuth session missing DID"),
                (Redirect::to("/login?error=did_extraction_failed")).into_response()
            )
        })?;

    let existing_account = Accounts::find()
        .filter(crate::orm::accounts::Column::Did.eq(did.to_string()))
        .one(&state.orm)
        .await
        .wrap_err("Failed to query existing account")
        .map_err(|e| {
            tracing::error!("Account query failed: {:?}", e);
            ServerError(e, (Redirect::to("/login?error=account_query_failed")).into_response())
        })?;

    let account = match existing_account {
        Some(account) => account,
        None => {
            let account = crate::orm::accounts::ActiveModel {
                did: ActiveValue::Set(did.to_string()),
                user_id: ActiveValue::Set(user.user_id),
                ..Default::default()
            };

            account
                .insert(&state.orm)
                .await
                .wrap_err("Failed to create account")
                .map_err(|e| {
                    tracing::error!("Account creation failed: {:?}", e);
                    ServerError(e, (Redirect::to("/login?error=account_creation_failed")).into_response())
                })?
        }
    };

    // The atrium session is already stored by the OAuth client

    let session = create_session_and_set_cookie(&state, &cookies, user.user_id, &account)
        .await
        .wrap_err("Failed to create session")
        .map_err(|e| {
            tracing::error!("Session creation failed: {:?}", e);
            ServerError(e, (Redirect::to("/login?error=session_creation_failed")).into_response())
        })?;

    let mut session_active: crate::orm::sessions::ActiveModel = session.into();
    session_active.primary_account_id = ActiveValue::Set(account.account_id);
    session_active
        .update(&state.orm)
        .await
        .wrap_err("Failed to update session with primary account")
        .map_err(|e| {
            tracing::error!("Session update failed: {:?}", e);
            ServerError(e, (Redirect::to("/login?error=session_update_failed")).into_response())
        })?;

    // Schedule a background job to update the display name and handle
    if let Err(err) = crate::jobs::UpdateProfileInfoJob::new(did.to_string())
        .enqueue(state.clone(), "callback".to_string())
        .await
    {
        // Log the error but continue - not fatal
        tracing::error!("Failed to enqueue display name update job: {:?}", err);
    } else {
        info!("Queued display name update job for DID: {}", did.to_string());
    }

    info!("Authentication successful for DID: {}", did.to_string());

    // Redirect to the profile page
    info!("Setting auth cookies and redirecting to /me");
    Ok(Redirect::to("/me"))
}
