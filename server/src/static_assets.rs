use include_dir::{include_dir, Dir};
use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::Response,
};
use mime_guess::from_path;

// Include the static directory in the binary
static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

// Serve static files from the embedded directory
pub async fn serve_static_file(Path(path): Path<String>) -> Result<Response<Vec<u8>>, StatusCode> {
    // Try to find the file in the embedded directory
    let file = STATIC_DIR
        .get_file(&path)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    // Get the file contents
    let contents = file.contents();
    
    // Guess the MIME type
    let mime_type = from_path(&path)
        .first_or_octet_stream()
        .to_string();
    
    // Create the response
    let response = Response::builder()
        .header(header::CONTENT_TYPE, mime_type)
        .header(header::CACHE_CONTROL, "public, max-age=31536000") // 1 year cache
        .body(contents.to_vec())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(response)
}

// Helper function to get an image URL relative to the site
pub fn image_url(path: &str) -> String {
    format!("/static/{}", path)
}

// Create reusable components for the logo
pub fn logo_img(class: &str) -> maud::Markup {
    maud::html! {
        a href="/" class="inline-block" {
            img 
                src=(image_url("PFP.png")) 
                alt="pfp.blue Logo" 
                class=(class) 
        }
    }
}

pub fn banner_img(class: &str) -> maud::Markup {
    maud::html! {
        a href="/" class="inline-block" {
            img 
                src=(image_url("Banner.png")) 
                alt="pfp.blue Banner" 
                class=(class) 
        }
    }
}