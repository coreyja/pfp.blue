use maud::{html, Markup, Render};
use crate::oauth::OAuthTokenSet;

pub struct AccountDropdown {
    pub tokens: Vec<OAuthTokenSet>,
    pub primary_did: String,
    pub current_path: String,
}

impl AccountDropdown {
    pub fn new(tokens: Vec<OAuthTokenSet>, primary_did: &str, current_path: &str) -> Self {
        Self {
            tokens,
            primary_did: primary_did.to_string(),
            current_path: current_path.to_string(),
        }
    }
}

impl Render for AccountDropdown {
    fn render(&self) -> Markup {
        html! {
            // CSS-only dropdown using the details/summary elements
            details class="relative inline-block text-left" {
                summary class="inline-flex justify-center w-full px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 border border-indigo-300 rounded-md shadow-sm hover:bg-indigo-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 cursor-pointer" {
                    // Show current primary account handle
                    @let primary_token = self.tokens.iter().find(|t| t.did == self.primary_did).unwrap_or(&self.tokens[0]);
                    span class="flex items-center gap-2" {
                        // Display name/handle with a dropdown arrow
                        span class="text-md font-medium" { 
                            @if let Some(display_name) = &primary_token.display_name {
                                "@" (display_name)
                            } @else {
                                "Account"
                            }
                        }
                        
                        // Dropdown arrow icon
                        svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" {
                            path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" {}
                        }
                    }
                }
                
                // Dropdown content
                div class="origin-top-right absolute right-0 mt-2 w-64 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-10 divide-y divide-gray-100" {
                    // Fixed position to avoid layout shifts with view-transitions
                    div class="py-1" {
                        // Account list section
                        div class="px-4 py-2 text-xs text-gray-500 uppercase tracking-wider" { "Your Accounts" }
                        
                        @for token in &self.tokens {
                            @let is_current = token.did == self.primary_did;
                            
                            // For each account, show a menu item
                            a href={"/oauth/bsky/set-primary?did=" (token.did) "&redirect=" (self.current_path)}
                              class="flex items-center px-4 py-2 text-sm hover:bg-gray-100 transition-colors duration-150" {
                                
                                // Show a checkmark for currently active account
                                div class="w-5 text-indigo-600 mr-3" {
                                    @if is_current {
                                        svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" {
                                            path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" {}
                                        }
                                    }
                                }
                                
                                // Account information
                                div {
                                    div class="font-medium" {
                                        @if let Some(display_name) = &token.display_name {
                                            "@" (display_name)
                                        } @else {
                                            "did:..." (token.did.chars().skip(token.did.len().saturating_sub(8)).collect::<String>())
                                        }
                                    }
                                    @if is_current {
                                        div class="text-xs text-indigo-600" { "Currently active" }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Add new account section
                    div class="py-1" {
                        a href="/oauth/bsky/authorize" class="flex items-center px-4 py-2 text-sm text-indigo-700 hover:bg-indigo-50 transition-colors duration-150" {
                            // Plus icon
                            div class="w-5 text-indigo-600 mr-3" {
                                svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" {
                                    path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" {}
                                }
                            }
                            span { "Link new account" }
                        }
                    }
                }
            }
        }
    }
}