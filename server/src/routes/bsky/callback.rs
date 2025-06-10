use atrium_oauth::CallbackParams;
use axum::{
    extract::{Query, State},
    response::{Redirect, Response},
};
use cja::{jobs::Job, server::cookies::CookieJar};
use sea_orm::{
    ActiveModelTrait as _, ActiveValue, ColumnTrait as _, EntityTrait as _, QueryFilter as _,
};
use tracing::info;

use crate::{
    auth::{create_session_and_set_cookie, OptionalUser},
    errors::ServerResult,
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

    let (oauth_session, _) = state.atrium.oauth.callback(params).await.unwrap();

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
                user_id: ActiveValue::Set(user.user_id),
                ..Default::default()
            };

            account.insert(&state.orm).await.unwrap()
        }
    };

    // The atrium session is already stored by the OAuth client

    let session = create_session_and_set_cookie(&state, &cookies, user.user_id, &account)
        .await
        .unwrap();

    let mut session_active: crate::orm::sessions::ActiveModel = session.into();
    session_active.primary_account_id = ActiveValue::Set(account.account_id);
    let session = session_active.update(&state.orm).await.unwrap();

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
