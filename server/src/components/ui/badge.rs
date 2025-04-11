use maud::{html, Markup, Render};

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum BadgeColor {
    Blue,
    Green,
    Red,
    Yellow,
    Purple,
    Pink,
    Indigo,
    Gray,
}

pub struct Badge {
    pub text: String,
    pub color: BadgeColor,
    pub rounded: bool,
    pub extra_classes: Option<String>,
}

impl Badge {
    pub fn new(text: &str, color: BadgeColor) -> Self {
        Self {
            text: text.to_string(),
            color,
            rounded: false,
            extra_classes: None,
        }
    }

    pub fn rounded(mut self, rounded: bool) -> Self {
        self.rounded = rounded;
        self
    }

    fn get_color_classes(&self) -> &'static str {
        match self.color {
            BadgeColor::Blue => "bg-blue-100 text-blue-800",
            BadgeColor::Green => "bg-green-100 text-green-800",
            BadgeColor::Red => "bg-red-100 text-red-800",
            BadgeColor::Yellow => "bg-yellow-100 text-yellow-800",
            BadgeColor::Purple => "bg-purple-100 text-purple-800",
            BadgeColor::Pink => "bg-pink-100 text-pink-800",
            BadgeColor::Indigo => "bg-indigo-100 text-indigo-800",
            BadgeColor::Gray => "bg-gray-100 text-gray-800",
        }
    }
}

impl Render for Badge {
    fn render(&self) -> Markup {
        let color_classes = self.get_color_classes();
        let rounded = if self.rounded {
            "rounded-full"
        } else {
            "rounded"
        };
        let extra_classes = self.extra_classes.as_deref().unwrap_or("");

        let classes = format!(
            "{} text-xs font-medium px-2 py-1 {} {}",
            color_classes, rounded, extra_classes
        );

        html! {
            span class=(classes) { (self.text) }
        }
    }
}
