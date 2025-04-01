use maud::{html, Markup};

pub struct Icon;

impl Icon {
    pub fn user() -> Markup {
        html! {
            i class="fa-solid fa-user" {}
        }
    }

    pub fn link() -> Markup {
        html! {
            i class="fa-solid fa-link" {}
        }
    }

    pub fn check() -> Markup {
        html! {
            i class="fa-solid fa-check" {}
        }
    }

    pub fn plus() -> Markup {
        html! {
            i class="fa-solid fa-plus" {}
        }
    }

    pub fn home() -> Markup {
        html! {
            i class="fa-solid fa-home" {}
        }
    }

    pub fn logout() -> Markup {
        html! {
            i class="fa-solid fa-sign-out-alt" {}
        }
    }

    pub fn login() -> Markup {
        html! {
            i class="fa-solid fa-sign-in-alt" {}
        }
    }

    pub fn app_logo() -> Markup {
        html! {
            i class="fa-solid fa-user-circle text-indigo-600 text-4xl sm:text-5xl" {}
        }
    }

    // Allows converting an icon to a string for buttons and other components
    pub fn into_string(self) -> String {
        "fa-solid fa-user".to_string()
    }

    // Static version for use with the icon methods
    pub fn markup_to_string(markup: Markup) -> String {
        markup.into_string()
    }
}
