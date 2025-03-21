use maud::{html, Markup, Render};

pub struct Heading {
    pub text: String,
    pub level: HeadingLevel,
    pub color: Option<String>,
    pub classes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HeadingLevel {
    H1,
    H2,
    H3,
    H4,
    H5,
    H6,
}

impl Heading {
    pub fn new(text: &str, level: HeadingLevel) -> Self {
        Self {
            text: text.to_string(),
            level,
            color: None,
            classes: None,
        }
    }

    pub fn h1(text: &str) -> Self {
        Self::new(text, HeadingLevel::H1)
    }

    pub fn h2(text: &str) -> Self {
        Self::new(text, HeadingLevel::H2)
    }

    pub fn h3(text: &str) -> Self {
        Self::new(text, HeadingLevel::H3)
    }

    pub fn with_color(mut self, color: &str) -> Self {
        self.color = Some(color.to_string());
        self
    }

    pub fn with_classes(mut self, classes: &str) -> Self {
        self.classes = Some(classes.to_string());
        self
    }

    fn default_classes_for_level(&self) -> &'static str {
        match self.level {
            HeadingLevel::H1 => "text-4xl font-bold mb-3",
            HeadingLevel::H2 => "text-3xl font-bold mb-2",
            HeadingLevel::H3 => "text-xl font-semibold mb-2",
            HeadingLevel::H4 => "text-lg font-medium mb-1",
            HeadingLevel::H5 => "text-base font-medium mb-1",
            HeadingLevel::H6 => "text-sm font-medium mb-1",
        }
    }
}

impl Render for Heading {
    fn render(&self) -> Markup {
        let default_classes = self.default_classes_for_level();
        let color_class = self.color.as_deref().unwrap_or("text-gray-800");
        let additional_classes = self.classes.as_deref().unwrap_or("");
        
        let classes = format!("{} {} {}", default_classes, color_class, additional_classes);

        match self.level {
            HeadingLevel::H1 => html! { h1 class=(classes) { (self.text) } },
            HeadingLevel::H2 => html! { h2 class=(classes) { (self.text) } },
            HeadingLevel::H3 => html! { h3 class=(classes) { (self.text) } },
            HeadingLevel::H4 => html! { h4 class=(classes) { (self.text) } },
            HeadingLevel::H5 => html! { h5 class=(classes) { (self.text) } },
            HeadingLevel::H6 => html! { h6 class=(classes) { (self.text) } },
        }
    }
}