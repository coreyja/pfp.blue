use atrium_api::did_doc::DidDocument;
use cja::jobs::Job;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

use crate::prelude::*;

/// Job to update a user's profile information (display name and handle) in the database
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateProfileInfoJob {
    /// The DID of the user - only thing we need to look up the token in the DB
    pub did: String,
}

impl UpdateProfileInfoJob {
    pub fn new(did: String) -> Self {
        Self { did }
    }
}

pub fn get_handle(did: &DidDocument) -> Option<String> {
    let aka = did.also_known_as.as_ref()?;

    aka.iter()
        .find_map(|handle| handle.strip_prefix("at://"))
        .map(|s| s.to_string())
}

use crate::orm::prelude::*;

#[async_trait::async_trait]
impl Job<AppState> for UpdateProfileInfoJob {
    const NAME: &'static str = "UpdateProfileInfoJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        let account = Accounts::find()
            .filter(crate::orm::accounts::Column::Did.eq(self.did.clone()))
            .one(&app_state.orm)
            .await
            .wrap_err_with(|| format!("Error retrieving account for DID {}", self.did))?;

        let account = account
            .ok_or_else(|| cja::color_eyre::eyre::eyre!("No account found for DID {}", self.did))?;

        // Get the atrium session for this DID
        let did = atrium_api::types::string::Did::new(self.did.clone())
            .map_err(|e| cja::color_eyre::eyre::eyre!("Invalid DID format: {}", e))?;

        let session = app_state.atrium.oauth.restore(&did).await?;
        let agent = atrium_api::agent::Agent::new(session);

        // Get the DID document to extract the handle
        let did_doc =
            crate::did::resolve_did_to_document(&did, app_state.bsky_client.clone()).await?;

        // Get the profile
        let profile = agent
            .api
            .app
            .bsky
            .actor
            .get_profile(
                atrium_api::app::bsky::actor::get_profile::ParametersData {
                    actor: did.clone().into(),
                }
                .into(),
            )
            .await?;

        // Extract handle from DID document (if available)
        let handle = get_handle(&did_doc);

        // Extract display name from profile
        let display_name = profile.data.display_name.clone();

        // Update the account with the latest information
        use sea_orm::ActiveModelTrait as _;
        let mut account_model: crate::orm::accounts::ActiveModel = account.into();

        if let Some(h) = handle {
            account_model.handle = sea_orm::ActiveValue::Set(Some(h));
        }

        if let Some(dn) = display_name {
            account_model.display_name = sea_orm::ActiveValue::Set(Some(dn));
        }

        account_model.update(&app_state.orm).await?;

        Ok(())
    }
}
