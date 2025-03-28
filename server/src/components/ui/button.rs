use maud::{html, Markup, Render};

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ButtonVariant {
    Primary,
    Secondary,
    Outline,
    Link,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ButtonSize {
    Small,
    Medium,
    Large,
}

pub struct Button {
    pub text: String,
    pub href: Option<String>,
    pub variant: ButtonVariant,
    pub size: ButtonSize,
    pub full_width: bool,
    pub icon: Option<String>,
    pub icon_position: IconPosition,
    pub button_type: Option<String>,
    pub extra_classes: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IconPosition {
    Left,
    Right,
}

impl Default for Button {
    fn default() -> Self {
        Self {
            text: String::new(),
            href: None,
            variant: ButtonVariant::Primary,
            size: ButtonSize::Medium,
            full_width: false,
            icon: None,
            icon_position: IconPosition::Left,
            button_type: None,
            extra_classes: None,
        }
    }
}

impl Button {
    pub fn new(text: &str) -> Self {
        Self {
            text: text.to_string(),
            ..Default::default()
        }
    }

    pub fn variant(mut self, variant: ButtonVariant) -> Self {
        self.variant = variant;
        self
    }

    pub fn primary(text: &str) -> Self {
        Self {
            text: text.to_string(),
            variant: ButtonVariant::Primary,
            ..Default::default()
        }
    }

    pub fn secondary(text: &str) -> Self {
        Self {
            text: text.to_string(),
            variant: ButtonVariant::Secondary,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    pub fn outline(text: &str) -> Self {
        Self {
            text: text.to_string(),
            variant: ButtonVariant::Outline,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    pub fn link(text: &str) -> Self {
        Self {
            text: text.to_string(),
            variant: ButtonVariant::Link,
            ..Default::default()
        }
    }

    pub fn href(mut self, href: &str) -> Self {
        self.href = Some(href.to_string());
        self
    }

    pub fn size(mut self, size: ButtonSize) -> Self {
        self.size = size;
        self
    }

    pub fn full_width(mut self, full_width: bool) -> Self {
        self.full_width = full_width;
        self
    }

    pub fn icon(mut self, icon: impl AsRef<str>, position: IconPosition) -> Self {
        self.icon = Some(icon.as_ref().to_string());
        self.icon_position = position;
        self
    }

    pub fn button_type(mut self, button_type: &str) -> Self {
        self.button_type = Some(button_type.to_string());
        self
    }

    #[allow(dead_code)]
    pub fn extra_classes(mut self, classes: &str) -> Self {
        self.extra_classes = Some(classes.to_string());
        self
    }

    fn get_variant_classes(&self) -> &'static str {
        match self.variant {
            ButtonVariant::Primary => "bg-indigo-600 hover:bg-indigo-700 text-white",
            ButtonVariant::Secondary => "bg-white hover:bg-gray-50 text-indigo-600 border border-indigo-300 hover:border-indigo-400",
            ButtonVariant::Outline => "bg-transparent hover:bg-gray-50 text-indigo-600 border border-indigo-300 hover:border-indigo-400",
            ButtonVariant::Link => "bg-transparent text-indigo-600 hover:text-indigo-800 hover:underline",
        }
    }

    fn get_size_classes(&self) -> &'static str {
        match self.size {
            ButtonSize::Small => "py-1 px-2 text-sm",
            ButtonSize::Medium => "py-2 px-4",
            ButtonSize::Large => "py-3 px-6 text-lg",
        }
    }
}

impl Render for Button {
    fn render(&self) -> Markup {
        let variant_classes = self.get_variant_classes();
        let size_classes = self.get_size_classes();
        let width_class = if self.full_width { "w-full" } else { "" };
        let extra_classes = self.extra_classes.as_deref().unwrap_or("");

        let base_classes = format!(
            "{} {} {} font-medium rounded-lg transition-colors duration-200 flex items-center justify-center {} {}",
            variant_classes, size_classes, width_class,
            if self.variant == ButtonVariant::Link { "" } else { "shadow-sm" },
            extra_classes
        );

        let icon_markup = match &self.icon {
            Some(icon) => html! { (maud::PreEscaped(icon)) },
            None => html! {},
        };

        if let Some(href) = &self.href {
            html! {
                a href=(href) class=(base_classes) {
                    @if self.icon_position == IconPosition::Left && self.icon.is_some() {
                        span class="mr-2" { (icon_markup) }
                    }

                    (self.text)

                    @if self.icon_position == IconPosition::Right && self.icon.is_some() {
                        span class="ml-2" { (icon_markup) }
                    }
                }
            }
        } else {
            let button_type = self.button_type.as_deref().unwrap_or("button");

            html! {
                button type=(button_type) class=(base_classes) {
                    @if self.icon_position == IconPosition::Left && self.icon.is_some() {
                        span class="mr-2" { (icon_markup) }
                    }

                    (self.text)

                    @if self.icon_position == IconPosition::Right && self.icon.is_some() {
                        span class="ml-2" { (icon_markup) }
                    }
                }
            }
        }
    }
}
