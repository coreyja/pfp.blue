#[cfg(test)]
mod tests {
    use pfp_blue::jobs::generate_progress_image;
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
