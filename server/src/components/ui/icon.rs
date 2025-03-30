use maud::{html, Markup, PreEscaped};

pub struct Icon;

impl Icon {
    pub fn user() -> Markup {
        html! {
            (PreEscaped(USER_ICON))
        }
    }

    pub fn link() -> Markup {
        html! {
            (PreEscaped(LINK_ICON))
        }
    }

    pub fn check() -> Markup {
        html! {
            (PreEscaped(CHECK_ICON))
        }
    }

    pub fn plus() -> Markup {
        html! {
            (PreEscaped(PLUS_ICON))
        }
    }

    pub fn home() -> Markup {
        html! {
            (PreEscaped(HOME_ICON))
        }
    }

    pub fn logout() -> Markup {
        html! {
            (PreEscaped(LOGOUT_ICON))
        }
    }

    pub fn login() -> Markup {
        html! {
            (PreEscaped(LOGIN_ICON))
        }
    }

    pub fn app_logo() -> Markup {
        html! {
            (PreEscaped(APP_LOGO_ICON))
        }
    }
}

// Constants to hold the icon SVG data
const USER_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>"#;

const LINK_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg>"#;

const CHECK_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>"#;

const PLUS_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" /></svg>"#;

const HOME_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7m-7-7v14" /></svg>"#;

const LOGOUT_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>"#;

const LOGIN_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" /></svg>"#;

const APP_LOGO_ICON: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="w-12 h-12 sm:w-16 sm:h-16 text-indigo-600">
  <path d="M12 2.5a5.5 5.5 0 0 1 3.096 10.047A8 8 0 0 1 19 19.95V20a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-.05a8 8 0 0 1 3.904-7.403A5.5 5.5 0 0 1 12 2.5z" fill="none" />
  <path d="M14 10l-4 2" stroke-width="1.5" />
  <path d="M10 8l4 2" stroke-width="1.5" />  
  <circle cx="12" cy="8" r="2.5" fill="currentColor" opacity="0.2" />
  <circle cx="10" cy="10" r="1" fill="currentColor" />
  <circle cx="14" cy="12" r="1" fill="currentColor" />
</svg>"#;
