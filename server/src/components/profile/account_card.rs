use maud::{html, Markup, Render};
use std::time::SystemTime;

pub struct AccountCard {
    pub did: String,
    pub handle: Option<String>,
    pub expires_at: u64,
    pub is_primary: bool,
}

impl AccountCard {
    pub fn new(did: &str, expires_at: u64) -> Self {
        Self {
            did: did.to_string(),
            handle: None,
            expires_at,
            is_primary: false,
        }
    }

    pub fn handle(mut self, handle: &str) -> Self {
        self.handle = Some(handle.to_string());
        self
    }

    pub fn is_primary(mut self, is_primary: bool) -> Self {
        self.is_primary = is_primary;
        self
    }
    
    fn get_expires_in_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if self.expires_at > now {
            self.expires_at - now
        } else {
            0
        }
    }
}

impl Render for AccountCard {
    fn render(&self) -> Markup {
        html! {
            div class="bg-white rounded-lg border border-gray-200 p-4 hover:shadow-md transition duration-200 relative overflow-hidden" {
                // Decorative element for primary account
                @if self.is_primary {
                    div class="absolute top-0 right-0" {
                        div class="bg-green-500 text-white text-xs transform rotate-45 px-8 py-1 translate-x-6 -translate-y-1 shadow-sm" {
                            "PRIMARY"
                        }
                    }
                }

                div class="flex flex-col sm:flex-row sm:items-center justify-between" {
                    div class="mb-2 sm:mb-0" {
                        @if let Some(handle) = &self.handle {
                            p class="font-medium text-gray-900 mb-1 truncate max-w-xs" { "@" (handle) }
                            p class="text-xs text-gray-500 mb-1 truncate max-w-xs" { (self.did) }
                        } @else {
                            p class="font-medium text-gray-900 mb-1 truncate max-w-xs" { (self.did) }
                        }
                        p class="text-sm text-gray-500" { "Expires in: " (self.get_expires_in_seconds()) " seconds" }
                    }

                    @if !self.is_primary {
                        a href={"/oauth/bsky/set-primary?did=" (self.did)}
                            class="text-sm bg-indigo-100 hover:bg-indigo-200 text-indigo-800 px-3 py-1 rounded-full inline-flex items-center transition-colors duration-200" {
                            "Set as Primary"
                        }
                    }
                }
            }
        }
    }
}