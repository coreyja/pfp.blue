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
            }

            // Main container with gradient background
            div class="min-h-screen bg-gradient-to-br from-blue-100 via-indigo-50 to-purple-100 py-8 px-4 sm:px-6 lg:px-8" {
                (self.content.render())

                // Footer credit
                div class="mt-8 text-center text-gray-500 text-sm" {
                    p { "© 2025 pfp.blue - Bluesky Profile Management" }
                }
            }
        }
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
            div class={(width_class) " mx-auto bg-white rounded-2xl shadow-xl overflow-hidden"} {
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
