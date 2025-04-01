use super::button::{Button, ButtonVariant, IconPosition};
use maud::{html, Markup, Render};

// Add Default implementation to fix clippy warning
#[derive(Default)]
pub struct NavButtons {
    pub items: Vec<NavButton>,
    pub container_classes: Option<String>,
}

pub struct NavButton {
    pub text: String,
    pub href: String,
    pub icon_type: Option<NavButtonIcon>,
    pub is_active: bool,
}

// Allow unused variants as they'll likely be used in the future
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum NavButtonIcon {
    Home,
    User,
    Logout,
    Login,
    Link,
    Plus,
    Check,
    Custom(String),
}

impl NavButtons {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            container_classes: None,
        }
    }

    #[allow(dead_code)]
    pub fn add_button(mut self, button: NavButton) -> Self {
        self.items.push(button);
        self
    }

    #[allow(dead_code)]
    pub fn container_classes(mut self, classes: &str) -> Self {
        self.container_classes = Some(classes.to_string());
        self
    }
}

impl NavButton {
    #[allow(dead_code)]
    pub fn new(text: &str, href: &str) -> Self {
        Self {
            text: text.to_string(),
            href: href.to_string(),
            icon_type: None,
            is_active: false,
        }
    }

    #[allow(dead_code)]
    pub fn with_icon(mut self, icon_type: NavButtonIcon) -> Self {
        self.icon_type = Some(icon_type);
        self
    }

    #[allow(dead_code)]
    pub fn active(mut self, is_active: bool) -> Self {
        self.is_active = is_active;
        self
    }

    fn get_icon_class(&self) -> String {
        if let Some(icon_type) = &self.icon_type {
            match icon_type {
                NavButtonIcon::Home => "<i class=\"fa-solid fa-home\"></i>".to_string(),
                NavButtonIcon::User => "<i class=\"fa-solid fa-user\"></i>".to_string(),
                NavButtonIcon::Logout => {
                    "<i class=\"fa-solid fa-right-from-bracket\"></i>".to_string()
                }
                NavButtonIcon::Login => {
                    "<i class=\"fa-solid fa-right-to-bracket\"></i>".to_string()
                }
                NavButtonIcon::Link => "<i class=\"fa-solid fa-link\"></i>".to_string(),
                NavButtonIcon::Plus => "<i class=\"fa-solid fa-plus\"></i>".to_string(),
                NavButtonIcon::Check => "<i class=\"fa-solid fa-check\"></i>".to_string(),
                NavButtonIcon::Custom(html) => html.clone(),
            }
        } else {
            String::new()
        }
    }
}

impl Render for NavButtons {
    fn render(&self) -> Markup {
        let classes = self
            .container_classes
            .as_deref()
            .unwrap_or("flex flex-wrap justify-center gap-3 pt-4 border-t border-gray-200");

        html! {
            div class=(classes) {
                @for button in &self.items {
                    (render_nav_button(button))
                }
            }
        }
    }
}

fn render_nav_button(button: &NavButton) -> Markup {
    let variant = if button.is_active {
        ButtonVariant::Primary
    } else {
        ButtonVariant::Link
    };

    let mut btn = Button::new(&button.text)
        .variant(variant)
        .href(&button.href);

    // Fix redundant pattern matching
    if button.icon_type.is_some() {
        btn = btn.icon(button.get_icon_class(), IconPosition::Left);
    }

    html! {
        (btn)
    }
}
