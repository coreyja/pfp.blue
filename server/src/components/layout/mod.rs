use maud::{html, Markup, Render};

pub struct Page {
    pub title: String,
    pub content: Box<dyn Render>,
}

impl Render for Page {
    fn render(&self) -> Markup {
        html! {
            head {
                title { (self.title) }
                script src="https://unpkg.com/@tailwindcss/browser@4" {}
                meta name="viewport" content="width=device-width, initial-scale=1.0";
            }

            // Main container - fullscreen on mobile, gradient background on larger screens
            div class="min-h-screen bg-white md:bg-gradient-to-br md:from-blue-100 md:via-indigo-50 md:to-purple-100 py-4 md:py-8 px-0 sm:px-4 md:px-6 lg:px-8" {
                (self.content.render())

                // Footer credit
                div class="mt-6 md:mt-8 text-center text-sm" {
                    p class="text-gray-500" { "© 2025 pfp.blue - Bluesky Profile Management" }
                    
                    // Social links
                    div class="mt-2 flex justify-center space-x-3" {
                        a href="https://bsky.app/profile/pfp.blue" target="_blank" 
                          class="inline-flex items-center text-blue-600 hover:text-blue-800" {
                            // Bluesky icon
                            svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="currentColor" {
                                path d="M12.001 3.5c-4.31 0-7.375 3.033-7.375 6.875 0 1.643.68 2.972 1.694 4.106a7.642 7.642 0 01-.568 1.343c-.204.484-.474.976-.803 1.438.887-.132 1.691-.399 2.37-.802.476-.27.916-.6 1.294-.991a9.457 9.457 0 003.388.632c4.31 0 7.375-3.033 7.375-6.875.001-3.776-3.133-6.726-7.375-6.726zm0 12.601a8.325 8.325 0 01-2.984-.569 1.15 1.15 0 00-1.242.225 4.573 4.573 0 01-1.234.85 5.82 5.82 0 01-.742.266c.24-.33.429-.674.581-1.014.263-.591.335-1.306.072-1.94a1.065 1.065 0 00-.14-.25c-.778-.883-1.275-1.896-1.275-3.294 0-3.157 2.569-5.726 5.726-5.726 3.431 0 6.226 2.396 6.226 5.726 0 3.126-2.46 5.726-5.988 5.726z" {}
                            }
                            span class="ml-1 text-xs" { "@pfp.blue" }
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
            div class={(width_class) " mx-auto bg-white rounded-lg sm:rounded-xl md:rounded-2xl border border-gray-100 shadow-md sm:shadow-lg md:shadow-xl overflow-hidden w-full transition-all duration-300"} {
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

    #[allow(dead_code)]
    pub fn with_content(mut self, content: impl Render + 'static) -> Self {
        self.content = Some(Box::new(content));
        self
    }
}

impl Render for CurvedHeader {
    fn render(&self) -> Markup {
        html! {
            div class={"relative " (self.height) " bg-gradient-to-r from-blue-500 to-indigo-600"} {
                @if let Some(content) = &self.content {
                    (content.render())
                }

                div class="absolute left-0 right-0 bottom-0" {
                    (maud::PreEscaped(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 100" class="w-full h-20 fill-white"><path d="M0,64L80,69.3C160,75,320,85,480,80C640,75,800,53,960,42.7C1120,32,1280,32,1360,32L1440,32L1440,100L1360,100C1280,100,1120,100,960,100C800,100,640,100,480,100C320,100,160,100,80,100L0,100Z"></path></svg>"#))
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

    #[allow(dead_code)]
    pub fn with_padding(mut self, padding: &str) -> Self {
        self.padding = padding.to_string();
        self
    }

    #[allow(dead_code)]
    pub fn with_negative_margin_top(mut self, margin: &str) -> Self {
        self.negative_margin_top = Some(margin.to_string());
        self
    }
}

impl Render for ContentSection {
    fn render(&self) -> Markup {
        let mut classes = self.padding.clone();

        if let Some(margin) = &self.negative_margin_top {
            classes = format!("{} {} relative z-10", classes, margin);
        }

        html! {
            div class=(classes) {
                (self.content.render())
            }
        }
    }
}
