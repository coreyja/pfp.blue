use maud::{html, Markup, Render};
use super::button::{Button, ButtonVariant, IconPosition};
use super::icon::Icon;

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
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            container_classes: None,
        }
    }

    pub fn add_button(mut self, button: NavButton) -> Self {
        self.items.push(button);
        self
    }

    pub fn container_classes(mut self, classes: &str) -> Self {
        self.container_classes = Some(classes.to_string());
        self
    }
}

impl NavButton {
    pub fn new(text: &str, href: &str) -> Self {
        Self {
            text: text.to_string(),
            href: href.to_string(),
            icon_type: None,
            is_active: false,
        }
    }

    pub fn with_icon(mut self, icon_type: NavButtonIcon) -> Self {
        self.icon_type = Some(icon_type);
        self
    }

    pub fn active(mut self, is_active: bool) -> Self {
        self.is_active = is_active;
        self
    }

    fn get_icon_svg(&self) -> String {
        if let Some(icon_type) = &self.icon_type {
            match icon_type {
                NavButtonIcon::Home => Icon::home().into_string(),
                NavButtonIcon::User => Icon::user().into_string(),
                NavButtonIcon::Logout => Icon::logout().into_string(),
                NavButtonIcon::Login => Icon::login().into_string(),
                NavButtonIcon::Link => Icon::link().into_string(),
                NavButtonIcon::Plus => Icon::plus().into_string(),
                NavButtonIcon::Check => Icon::check().into_string(),
                NavButtonIcon::Custom(svg) => svg.clone(),
            }
        } else {
            String::new()
        }
    }
}

impl Render for NavButtons {
    fn render(&self) -> Markup {
        let classes = self.container_classes.as_deref().unwrap_or("flex flex-wrap justify-center gap-3 pt-4 border-t border-gray-200");
        
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
    
    if let Some(_) = &button.icon_type {
        btn = btn.icon(button.get_icon_svg(), IconPosition::Left);
    }
    
    html! {
        (btn)
    }
}