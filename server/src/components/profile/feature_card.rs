use maud::{html, Markup, Render};

pub struct FeatureCard {
    pub title: String,
    pub description: String,
    pub emoji: String,
    pub color: FeatureCardColor,
}

#[derive(Debug, Clone, PartialEq)]

pub enum FeatureCardColor {
    Blue,
    Indigo,
    Purple,
    #[allow(dead_code)]
    Pink,
}

impl FeatureCard {
    pub fn new(title: &str, description: &str, emoji: &str, color: FeatureCardColor) -> Self {
        Self {
            title: title.to_string(),
            description: description.to_string(),
            emoji: emoji.to_string(),
            color,
        }
    }

    fn get_background_color(&self) -> &'static str {
        match self.color {
            FeatureCardColor::Blue => "bg-blue-50",
            FeatureCardColor::Indigo => "bg-indigo-50",
            FeatureCardColor::Purple => "bg-purple-50",
            FeatureCardColor::Pink => "bg-pink-50",
        }
    }

    fn get_icon_bg_color(&self) -> &'static str {
        match self.color {
            FeatureCardColor::Blue => "bg-blue-100",
            FeatureCardColor::Indigo => "bg-indigo-100",
            FeatureCardColor::Purple => "bg-purple-100",
            FeatureCardColor::Pink => "bg-pink-100",
        }
    }

    fn get_title_color(&self) -> &'static str {
        match self.color {
            FeatureCardColor::Blue => "text-blue-800",
            FeatureCardColor::Indigo => "text-indigo-800",
            FeatureCardColor::Purple => "text-purple-800",
            FeatureCardColor::Pink => "text-pink-800",
        }
    }

    fn get_icon_color(&self) -> &'static str {
        match self.color {
            FeatureCardColor::Blue => "text-blue-600",
            FeatureCardColor::Indigo => "text-indigo-600",
            FeatureCardColor::Purple => "text-purple-600",
            FeatureCardColor::Pink => "text-pink-600",
        }
    }
}

impl Render for FeatureCard {
    fn render(&self) -> Markup {
        let bg_color = self.get_background_color();
        let icon_bg = self.get_icon_bg_color();
        let title_color = self.get_title_color();
        let icon_color = self.get_icon_color();

        html! {
            div class={(bg_color) " p-4 sm:p-5 rounded-lg sm:rounded-xl text-left transition-all duration-200 hover:shadow-sm"} {
                div class="flex items-center gap-3 mb-2 sm:mb-3" {
                    div class={"w-8 h-8 sm:w-10 sm:h-10 rounded-full " (icon_bg) " flex items-center justify-center " (icon_color) " text-lg sm:text-xl"} {
                        (self.emoji)
                    }
                    h3 class={"font-medium " (title_color) " text-sm sm:text-base"} { (self.title) }
                }
                p class="text-xs sm:text-sm text-gray-600 leading-relaxed" { (self.description) }
            }
        }
    }
}
