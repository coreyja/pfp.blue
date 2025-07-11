use maud::{html, Markup, Render};

pub struct Page {
    pub title: String,
    pub content: Box<dyn Render>,
}

impl Page {
    pub fn new(title: String, content: Box<dyn Render>) -> Self {
        Self { title, content }
    }

    // We can add any new Page methods here if needed in the future
}

impl Render for Page {
    fn render(&self) -> Markup {
        use crate::static_assets;

        html! {
            head {
                title { (self.title) }
                script src="https://unpkg.com/@tailwindcss/browser@4" {}
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                link rel="stylesheet" href="https://kit.fontawesome.com/e62c3d1513.css" crossorigin="anonymous";
                link rel="stylesheet" href="/static/styles.css";
                link rel="icon" href=(static_assets::image_url("PFP.png")) type="image/png";
                script src="/static/viewTransition.js" {}
            }

            // Main container - fullscreen on mobile, gradient background on larger screens
            div class="min-h-screen bg-white md:bg-gradient-to-br md:from-blue-100 md:via-indigo-50 md:to-purple-100 py-4 md:py-8 px-0 sm:px-4 md:px-6 lg:px-8" {
                (self.content.render())

                // Footer credit
                div class="mt-6 md:mt-8 text-center text-sm" {
                    p class="text-gray-500" { "© 2025 pfp.blue - Bluesky Profile Management" }

                    // Social links and footer nav
                    div class="mt-2 flex flex-col md:flex-row justify-center items-center gap-y-2 md:gap-x-6" {
                        // Social links
                        div class="flex justify-center space-x-3" {
                            a href="https://bsky.app/profile/pfp.blue" target="_blank"
                              class="inline-flex items-center text-blue-600 hover:text-blue-800 cursor-pointer" {
                                // Bluesky icon
                                i class="fa-brands fa-bluesky" {}
                                span class="ml-1 text-xs" { "@pfp.blue" }
                            }
                        }

                        // Footer navigation
                        div class="flex justify-center space-x-6 text-xs text-gray-500" {
                            a href="/about" class="hover:text-gray-700 hover:underline cursor-pointer" { "About" }
                            a href="/privacy" class="hover:text-gray-700 hover:underline cursor-pointer" { "Privacy Policy" }
                        }
                    }
                }
            }
        }
    }
}

impl axum::response::IntoResponse for Page {
    fn into_response(self) -> axum::response::Response {
        self.render().into_response()
    }
}

pub struct Card {
    pub content: Box<dyn Render>,
    pub max_width: Option<String>,
}

impl Card {
    pub fn new(content: impl Render + 'static) -> Self {
        Self {
            content: Box::new(content),
            max_width: None,
        }
    }

    pub fn with_max_width(mut self, max_width: &str) -> Self {
        self.max_width = Some(max_width.to_string());
        self
    }
}

impl Render for Card {
    fn render(&self) -> Markup {
        let width_class = self.max_width.as_deref().unwrap_or("max-w-md");

        html! {
            div class={(width_class) " mx-auto bg-white rounded-lg sm:rounded-xl md:rounded-2xl border border-gray-100 shadow-md sm:shadow-lg md:shadow-xl overflow-hidden w-full transition-all duration-300 view-transition-main-content"} {
                (self.content.render())
            }
        }
    }
}

pub struct CurvedHeader {
    pub height: String,
    pub content: Option<Box<dyn Render>>,
}

impl CurvedHeader {
    pub fn new(height: &str) -> Self {
        Self {
            height: height.to_string(),
            content: None,
        }
    }
}

impl Render for CurvedHeader {
    fn render(&self) -> Markup {
        use crate::static_assets;

        html! {
            div class="relative mb-8" {
                // The curved header background
                div class={"relative " (self.height) " bg-gradient-to-r from-blue-500 to-indigo-600"} {
                    // Curved bottom svg
                    div class="absolute left-0 right-0 bottom-0" {
                        (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 100" class="w-full h-12 sm:h-16 fill-white"><path d="M0,64L80,69.3C160,75,320,85,480,80C640,75,800,53,960,42.7C1120,32,1280,32,1360,32L1440,32L1440,100L1360,100C1280,100,1120,100,960,100C800,100,640,100,480,100C320,100,160,100,80,100L0,100Z"></path></svg>"#))
                    }

                    // Content inside the header (if provided)
                    @if let Some(content) = &self.content {
                        div class="h-full flex items-center justify-center text-white" {
                            (content.render())
                        }
                    } @else {
                        // Default content with logo centered
                        div class="flex justify-center items-center h-16 sm:h-24 py-4" {
                            (static_assets::logo_img("w-12 h-12 sm:w-16 sm:h-16 shadow-md rounded-full border-2 border-white bg-white"))
                        }
                    }
                }
            }
        }
    }
}

pub struct ContentSection {
    pub padding: String,
    pub content: Box<dyn Render>,
    pub negative_margin_top: Option<String>,
}

impl ContentSection {
    pub fn new(content: impl Render + 'static) -> Self {
        Self {
            padding: "px-8 py-6".to_string(),
            content: Box::new(content),
            negative_margin_top: None,
        }
    }
}

impl Render for ContentSection {
    fn render(&self) -> Markup {
        let mut classes = self.padding.clone();

        if let Some(margin) = &self.negative_margin_top {
            classes = format!("{classes} {margin} relative z-10");
        }

        html! {
            div class=(classes) {
                (self.content.render())
            }
        }
    }
}
