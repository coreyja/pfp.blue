use include_dir::{include_dir, Dir};
use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::IntoResponse,
};
use mime_guess::from_path;
use maud::Markup;

// Include the static directory in the binary
static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

// Serve static files from the embedded directory
pub async fn serve_static_file(Path(path): Path<String>) -> impl IntoResponse {
    // Try to find the file in the embedded directory
    if let Some(file) = STATIC_DIR.get_file(&path) {
        // Get the file contents
        let contents = file.contents().to_vec();
        
        // Guess the MIME type
        let mime_type = from_path(&path)
            .first_or_octet_stream()
            .to_string();
        
        // Create the response with headers
        (
            [
                (header::CONTENT_TYPE, mime_type),
                (header::CACHE_CONTROL, "public, max-age=31536000".to_string()),
            ],
            contents
        ).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// Helper function to get an image URL relative to the site
pub fn image_url(path: &str) -> String {
    format!("/static/{}", path)
}

// Create reusable components for the logo
pub fn logo_img(class: &str) -> Markup {
    maud::html! {
        a href="/" class="inline-block" {
            img 
                src=(image_url("PFP.png")) 
                alt="pfp.blue Logo" 
                class=(class);
        }
    }
}

pub fn banner_img(class: &str) -> Markup {
    maud::html! {
        a href="/" class="inline-block" {
            img 
                src=(image_url("Banner.png")) 
                alt="pfp.blue Banner" 
                class=(class);
        }
    }
}