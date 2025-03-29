use cja::{
    server::run_server,
    setup::{setup_sentry, setup_tracing},
};
use tracing::info;

mod api;
mod auth;
mod components;
mod cron;
mod did;
mod encryption;
mod errors;
mod jobs;
mod oauth;
mod profile_progress;
mod routes;
mod state;
mod user;

use state::AppState;

fn main() -> color_eyre::Result<()> {
    // Initialize Sentry for error tracking
    let _sentry_guard = setup_sentry();

    // Create and run the tokio runtime
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?
        .block_on(async { run_application().await })
}

async fn run_application() -> cja::Result<()> {
    // Initialize tracing
    setup_tracing("domains")?;

    // Initialize application state
    println!("\n========== 🔑 PFP.BLUE STARTING ==========");
    println!("Verifying OAuth keys...");

    let app_state = AppState::from_env().await?;

    // Spawn application tasks
    info!("Spawning application tasks");
    let futures = spawn_application_tasks(app_state).await?;

    // Wait for all tasks to complete
    futures::future::try_join_all(futures).await?;

    Ok(())
}

/// Spawn all application background tasks
async fn spawn_application_tasks(
    app_state: AppState,
) -> cja::Result<Vec<tokio::task::JoinHandle<cja::Result<()>>>> {
    let mut futures = vec![];

    if is_feature_enabled("SERVER") {
        info!("Server Enabled");
        futures.push(tokio::spawn(run_server(routes::routes(app_state.clone()))));
    } else {
        info!("Server Disabled");
    }

    // Initialize job worker if enabled
    if is_feature_enabled("JOBS") {
        info!("Jobs Enabled");
        futures.push(tokio::spawn(cja::jobs::worker::job_worker(
            app_state.clone(),
            jobs::Jobs,
        )));
    } else {
        info!("Jobs Disabled");
    }

    // Initialize cron worker if enabled
    if is_feature_enabled("CRON") {
        info!("Cron Enabled");
        futures.push(tokio::spawn(cron::run_cron(app_state.clone())));
    } else {
        info!("Cron Disabled");
    }

    info!("All application tasks spawned successfully");
    Ok(futures)
}

/// Check if a feature is enabled based on environment variables
fn is_feature_enabled(feature: &str) -> bool {
    std::env::var(format!("{}_DISABLED", feature)).unwrap_or_else(|_| "false".to_string()) != "true"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_is_feature_enabled_when_env_var_not_set() -> cja::Result<()> {
        // Ensure the environment variable is not set
        env::remove_var("TEST_FEATURE_DISABLED");

        // Feature should be enabled when env var is not set
        assert!(is_feature_enabled("TEST_FEATURE"));

        Ok(())
    }

    #[test]
    fn test_is_feature_enabled_when_env_var_is_false() -> cja::Result<()> {
        // Set the environment variable to "false"
        env::set_var("TEST_FEATURE_DISABLED", "false");

        // Feature should be enabled when env var is "false"
        assert!(is_feature_enabled("TEST_FEATURE"));

        // Clean up
        env::remove_var("TEST_FEATURE_DISABLED");

        Ok(())
    }

    #[test]
    fn test_is_feature_disabled_when_env_var_is_true() -> cja::Result<()> {
        // Set the environment variable to "true"
        env::set_var("TEST_FEATURE_DISABLED", "true");

        // Feature should be disabled when env var is "true"
        assert!(!is_feature_enabled("TEST_FEATURE"));

        // Clean up
        env::remove_var("TEST_FEATURE_DISABLED");

        Ok(())
    }

    #[test]
    fn test_is_feature_enabled_with_other_values() -> cja::Result<()> {
        // Set the environment variable to something other than "true"
        env::set_var("TEST_FEATURE_DISABLED", "yes");

        // Feature should be enabled when env var is not exactly "true"
        assert!(is_feature_enabled("TEST_FEATURE"));

        // Clean up
        env::remove_var("TEST_FEATURE_DISABLED");

        Ok(())
    }

    use crate::jobs::helpers::generate_progress_image;
    use std::fs;
    use std::path::Path;

    #[tokio::test]
    async fn test_generate_progress_images() {
        // This test generates sample progress images for visual inspection

        let test_dir = Path::new("./test-output");
        if !test_dir.exists() {
            fs::create_dir_all(test_dir).expect("Failed to create test output directory");
        }

        // Load a sample image
        // For the test, we'll use a simple gradient
        let width = 400;
        let height = 400;
        let mut img_buffer = image::RgbaImage::new(width, height);

        // Create a simple gradient circle
        for y in 0..height {
            for x in 0..width {
                let dx = x as f32 - width as f32 / 2.0;
                let dy = y as f32 - height as f32 / 2.0;
                let distance = (dx * dx + dy * dy).sqrt();

                // Create a circular gradient
                if distance < width as f32 / 2.0 {
                    let normalized_distance = distance / (width as f32 / 2.0);
                    let intensity = (1.0 - normalized_distance) * 255.0;
                    img_buffer.put_pixel(
                        x,
                        y,
                        image::Rgba([
                            intensity as u8,
                            (intensity * 0.5) as u8,
                            (intensity * 0.8) as u8,
                            255,
                        ]),
                    );
                } else {
                    img_buffer.put_pixel(x, y, image::Rgba([0, 0, 0, 0])); // Transparent outside circle
                }
            }
        }

        // Convert the test image to PNG bytes
        let mut original_buffer = Vec::new();
        img_buffer
            .write_to(
                &mut std::io::Cursor::new(&mut original_buffer),
                image::ImageFormat::Png,
            )
            .expect("Failed to encode original image");

        // Save the original image
        fs::write(test_dir.join("original.png"), &original_buffer)
            .expect("Failed to save original image");

        // Test progress values
        let progress_values = [0.0, 0.25, 0.5, 0.75, 1.0];

        for progress in progress_values {
            // Use the actual generate_progress_image function from the codebase
            let progress_image_data = generate_progress_image(&original_buffer, progress)
                .await
                .expect("Failed to generate progress image");

            // Save the generated image
            let filename = format!("progress_{:.2}.png", progress);
            fs::write(test_dir.join(filename), &progress_image_data).expect("Failed to save image");

            println!(
                "Generated progress image with progress value: {:.2}",
                progress
            );
        }

        println!(
            "Test images generated in {:?}",
            test_dir.canonicalize().unwrap()
        );
    }
}
