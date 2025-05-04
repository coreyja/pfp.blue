use cja::jobs::Job;
use color_eyre::eyre::eyre;
use color_eyre::eyre::Context as _;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::{
    jobs::helpers::{
        extract_progress_from_display_name, generate_progress_image, get_original_profile_picture,
        update_profile_with_image, upload_image_to_bluesky,
    },
    state::AppState,
};

/// Job to update a user's profile picture with progress visualization
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateProfilePictureProgressJob {
    /// The token ID to process
    pub token_id: uuid::Uuid,
}

impl UpdateProfilePictureProgressJob {
    /// Create a new job from a token ID
    pub fn new(token_id: uuid::Uuid) -> Self {
        Self { token_id }
    }
}

#[async_trait::async_trait]
impl Job<AppState> for UpdateProfilePictureProgressJob {
    const NAME: &'static str = "UpdateProfilePictureProgressJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        todo!()
        // Get the token ID's DID first
        // let token_info = sqlx::query!(
        //     r#"
        //     SELECT did FROM oauth_tokens WHERE id = $1
        //     "#,
        //     self.token_id
        // )
        // .fetch_optional(&app_state.db)
        // .await?
        // .ok_or_else(|| eyre!("No token found for ID {} in job", self.token_id))?;

        // crate::jobs::job_types::UpdateProfileInfoJob {
        //     did: token_info.did.clone(),
        // }
        // .run(app_state.clone())
        // .await?;

        // // Use our consolidated function to get a valid token
        // let token = crate::oauth::get_valid_token_by_did(&token_info.did, &app_state)
        //     .await
        //     .wrap_err_with(|| format!("Failed to get valid token for DID {}", token_info.did))?;

        // // Get the progress settings for this token
        // let progress = crate::profile_progress::ProfilePictureProgress::get_by_token_id(
        //     &app_state.db,
        //     self.token_id,
        // )
        // .await?
        // .ok_or_else(|| {
        //     eyre!(
        //         "No progress settings found for token ID {} in job",
        //         self.token_id
        //     )
        // })?;

        // // Check if the feature is enabled
        // if !progress.enabled {
        //     debug!(
        //         "Profile picture progress feature is disabled for token ID {}",
        //         self.token_id
        //     );
        //     return Ok(());
        // }

        // // Get the original profile picture blob from our custom collection
        // let original_blob = get_original_profile_picture(&app_state, &token)
        //     .await
        //     .wrap_err_with(|| {
        //         format!(
        //             "Failed to check for original profile picture for token ID {}",
        //             self.token_id
        //         )
        //     })?;

        // // Extract the CID (link) from the blob object retrieved from PDS
        // let pds_original_blob_cid = if let Some(blob_ref) = original_blob.get("ref") {
        //     blob_ref
        //         .get("$link")
        //         .and_then(|l| l.as_str())
        //         .map(|s| s.to_string())
        //         .ok_or_else(|| eyre!("Original blob object has no valid $link field"))?
        // } else {
        //     Err(eyre!("Original blob object has no ref field"))?
        // };

        // debug!(
        //     "Using original blob CID from PDS: {}",
        //     pds_original_blob_cid
        // );

        // // Extract progress fraction or percentage from display_name
        // let (numerator, denominator) = match &token.display_name {
        //     Some(display_name) => {
        //         extract_progress_from_display_name(display_name).unwrap_or((0.0, 1.0))
        //     }
        //     None => {
        //         debug!(
        //             "No display name found for token ID {}, defaulting to 0%",
        //             self.token_id
        //         );
        //         (0.0, 1.0)
        //     }
        // };

        // // Calculate the progress percentage
        // let progress_percentage = numerator / denominator;
        // debug!(
        //     "Progress for token {}: {}/{} = {:.2}%",
        //     self.token_id,
        //     numerator,
        //     denominator,
        //     progress_percentage * 100.0
        // );

        // // Fetch the original profile picture using the CID from PDS
        // let original_image_data = match crate::routes::bsky::fetch_blob_by_cid(
        //     &token.did,
        //     &pds_original_blob_cid,
        //     &app_state,
        // )
        // .await
        // {
        //     Ok(data) => data,
        //     Err(err) => {
        //         error!("Failed to fetch original profile picture: {:?}", err);
        //         return Err(eyre!("Failed to fetch original profile picture: {}", err));
        //     }
        // };

        // // Generate the progress image
        // let progress_image_data =
        //     match generate_progress_image(&original_image_data, progress_percentage).await {
        //         Ok(data) => {
        //             info!(
        //                 "Successfully generated progress image for token ID {}",
        //                 self.token_id
        //             );
        //             data
        //         }
        //         Err(err) => {
        //             error!("Failed to generate progress image: {:?}", err);
        //             return Err(err);
        //         }
        //     };

        // // Upload the new image to Bluesky
        // match upload_image_to_bluesky(&app_state, &token, &progress_image_data).await {
        //     Ok(blob_object) => {
        //         info!("Successfully uploaded progress image to Bluesky");

        //         // Update profile with the new image blob
        //         match update_profile_with_image(&app_state, &token, blob_object).await {
        //             Ok(_) => {
        //                 info!(
        //                     "Successfully updated profile with progress image for token ID {}",
        //                     self.token_id
        //                 );
        //             }
        //             Err(err) => {
        //                 error!("Failed to update profile with progress image: {:?}", err);
        //                 return Err(err);
        //             }
        //         }
        //     }
        //     Err(err) => {
        //         error!("Failed to upload progress image to Bluesky: {:?}", err);
        //         return Err(err);
        //     }
        // }

        // Ok(())
    }
}
