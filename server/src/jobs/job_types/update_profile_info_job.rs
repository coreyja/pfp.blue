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

        todo!("Use atrium client here and this should be really easy")
    }
}
