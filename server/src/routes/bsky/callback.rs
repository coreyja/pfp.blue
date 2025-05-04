use atrium_oauth::CallbackParams;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Redirect, Response},
};
use cja::{app_state::AppState as _, server::cookies::CookieJar};
use sea_orm::{
    ActiveModelTrait as _, ActiveValue, ColumnTrait as _, EntityTrait as _, QueryFilter as _,
};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    auth::{create_session_and_set_cookie, OptionalUser},
    errors::ServerResult,
    oauth::{self, OAuthTokenSet},
    state::AppState,
};

use crate::orm::prelude::*;

pub async fn callback(
    State(state): State<AppState>,
    cookies: CookieJar<AppState>,
    Query(params): Query<CallbackParams>,
    OptionalUser { user, session }: OptionalUser,
) -> ServerResult<Redirect, Response> {
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

    let did = oauth_session.did().await.unwrap();

    let existing_account = Accounts::find()
        .filter(crate::orm::accounts::Column::Did.eq(did.to_string()))
        .one(&state.orm)
        .await;

    let account = match existing_account {
        Ok(Some(account)) => account,
        _ => {
            let account = crate::orm::accounts::ActiveModel {
                did: ActiveValue::Set(did.to_string()),
                user_id: ActiveValue::Set(user.id),
                ..Default::default()
            };

            account.insert(&state.orm).await.unwrap()
        }
    };

    let session = create_session_and_set_cookie(&state, &cookies, user.id, &account)
        .await
        .unwrap();

    let mut session: crate::orm::sessions::ActiveModel = session.into();
    session.primary_token_id = ActiveValue::Set(Some(account.account_id));

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
