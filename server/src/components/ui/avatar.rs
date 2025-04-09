use maud::{html, Markup, Render};

pub struct Avatar {
    pub src: Option<String>,
    pub alt: String,
    pub size: String,
    pub border: bool,
    pub placeholder_text: Option<String>,
}

impl Avatar {
    
    pub fn new(src: Option<String>, alt: &str) -> Self {
        Self {
            src,
            alt: alt.to_string(),
            size: "w-12 h-12".to_string(),
            border: false,
            placeholder_text: None,
        }
    }

    
    pub fn size(mut self, size: &str) -> Self {
        self.size = size.to_string();
        self
    }

    
    pub fn with_border(mut self, border: bool) -> Self {
        self.border = border;
        self
    }

    
    pub fn placeholder_text(mut self, text: &str) -> Self {
        self.placeholder_text = Some(text.to_string());
        self
    }
}

impl Render for Avatar {
    fn render(&self) -> Markup {
        let border_class = if self.border {
            "border-4 border-white shadow-lg"
        } else {
            ""
        };

        html! {
            div class={"rounded-full overflow-hidden " (self.size) " " (border_class)} {
                @if let Some(src) = &self.src {
                    img src=(src) alt=(self.alt) class="w-full h-full object-cover" {}
                } @else {
                    div class={"bg-gradient-to-br from-blue-300 to-indigo-300 w-full h-full flex items-center justify-center text-white font-bold"} {
                        (self.placeholder_text.as_deref().unwrap_or("?"))
                    }
                }
            }
        }
    }
}
