use cja::jobs::Job;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// Job to update a user's profile picture with progress visualization
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateProfilePictureProgressJob {
    /// The account ID to process
    pub account_id: uuid::Uuid,
}

impl UpdateProfilePictureProgressJob {
    /// Create a new job from an account ID
    pub fn new(account_id: uuid::Uuid) -> Self {
        Self { account_id }
    }
}

#[async_trait::async_trait]
impl Job<AppState> for UpdateProfilePictureProgressJob {
    const NAME: &'static str = "UpdateProfilePictureProgressJob";

    async fn run(&self, app_state: AppState) -> cja::Result<()> {
        use crate::prelude::*;
        use color_eyre::eyre::{eyre, WrapErr};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use tracing::{debug, error, info};

        // Get the account
        let account = Accounts::find()
            .filter(crate::orm::accounts::Column::AccountId.eq(self.account_id))
            .one(&app_state.orm)
            .await
            .wrap_err_with(|| format!("Error retrieving account for ID {}", self.account_id))?
            .ok_or_else(|| eyre!("No account found for ID {}", self.account_id))?;

        // Update the profile info first to get the latest display name
        crate::jobs::job_types::UpdateProfileInfoJob::new(account.did.clone())
            .run(app_state.clone())
            .await?;

        // Get the progress settings for this account
        let progress = crate::orm::profile_picture_progress::Entity::find()
            .filter(crate::orm::profile_picture_progress::Column::AccountId.eq(self.account_id))
            .one(&app_state.orm)
            .await?
            .ok_or_else(|| {
                eyre!(
                    "No progress settings found for account ID {}",
                    self.account_id
                )
            })?;

        // Check if the feature is enabled
        if !progress.enabled {
            debug!(
                "Profile picture progress feature is disabled for account ID {}",
                self.account_id
            );
            return Ok(());
        }

        // Get the original profile picture blob from our custom collection
        let original_blob =
            crate::jobs::helpers::get_original_profile_picture(&app_state, &account)
                .await
                .wrap_err_with(|| {
                    format!(
                        "Failed to check for original profile picture for account ID {}",
                        self.account_id
                    )
                })?;

        // Extract progress fraction or percentage from display_name
        let account = Accounts::find()
            .filter(crate::orm::accounts::Column::AccountId.eq(self.account_id))
            .one(&app_state.orm)
            .await?
            .ok_or_else(|| eyre!("Account not found after update"))?;

        let (numerator, denominator) = match &account.display_name {
            Some(display_name) => {
                crate::jobs::helpers::extract_progress_from_display_name(display_name)
                    .unwrap_or((0.0, 1.0))
            }
            None => {
                debug!(
                    "No display name found for account ID {}, defaulting to 0%",
                    self.account_id
                );
                (0.0, 1.0)
            }
        };

        // Calculate the progress percentage
        let progress_percentage = numerator / denominator;
        debug!(
            "Progress for account {}: {}/{} = {:.2}%",
            self.account_id,
            numerator,
            denominator,
            progress_percentage * 100.0
        );

        // Extract the CID (link) from the blob object retrieved from PDS
        let pds_original_blob_cid =
            if let Some(blob_ref) = original_blob.get("blob").and_then(|b| b.get("ref")) {
                blob_ref
                    .get("$link")
                    .and_then(|l| l.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| eyre!("Original blob object has no valid $link field"))?
            } else {
                Err(eyre!("Original blob object has no ref field"))?
            };

        debug!(
            "Using original blob CID from PDS: {}",
            pds_original_blob_cid
        );

        // Fetch the original profile picture using the CID from PDS
        let original_image_data = match crate::routes::bsky::fetch_blob_by_cid(
            &account.did,
            &pds_original_blob_cid,
            &app_state,
        )
        .await
        {
            Ok(data) => data,
            Err(err) => {
                error!("Failed to fetch original profile picture: {:?}", err);
                return Err(eyre!("Failed to fetch original profile picture: {}", err));
            }
        };

        let original_img = image::load_from_memory(&original_image_data)
            .wrap_err("Failed to load original image")?;

        // Generate the progress image
        let progress_image_data =
            match crate::jobs::helpers::generate_progress_image(&original_img, progress_percentage)
                .await
            {
                Ok(data) => {
                    info!(
                        "Successfully generated progress image for account ID {}",
                        self.account_id
                    );
                    data
                }
                Err(err) => {
                    error!("Failed to generate progress image: {:?}", err);
                    return Err(err);
                }
            };

        const MAX_IMAGE_SIZE_BYTES: usize = 1000 * 1000;

        let mut size_multiplier = 1.0;
        let mut resized_image = crate::jobs::helpers::to_sized_png(
            progress_image_data.clone(),
            original_img.width(),
            original_img.height(),
        )
        .await?;

        while resized_image.len() > MAX_IMAGE_SIZE_BYTES {
            size_multiplier -= 0.1;

            let new_width = (original_img.width() as f64 * size_multiplier) as u32;
            let new_height = (original_img.height() as f64 * size_multiplier) as u32;
            resized_image = crate::jobs::helpers::to_sized_png(
                progress_image_data.clone(),
                new_width,
                new_height,
            )
            .await?;

            if size_multiplier < 0.1 {
                error!(
                    "Failed to resize image below max size for account ID {}. Current size: {} bytes",
                    self.account_id,
                    resized_image.len()
                );
                break;
            }
        }

        // Upload the new image to Bluesky
        match crate::jobs::helpers::upload_image_to_bluesky(&app_state, &account, &resized_image)
            .await
        {
            Ok(blob_object) => {
                info!("Successfully uploaded progress image to Bluesky");

                // Update profile with the new image blob
                match crate::jobs::helpers::update_profile_with_image(
                    &app_state,
                    &account,
                    blob_object,
                )
                .await
                {
                    Ok(_) => {
                        info!(
                            "Successfully updated profile with progress image for account ID {}",
                            self.account_id
                        );
                    }
                    Err(err) => {
                        error!("Failed to update profile with progress image: {:?}", err);
                        return Err(err);
                    }
                }
            }
            Err(err) => {
                error!("Failed to upload progress image to Bluesky: {:?}", err);
                return Err(err);
            }
        }

        Ok(())
    }
}
