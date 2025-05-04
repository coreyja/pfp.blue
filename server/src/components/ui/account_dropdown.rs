use maud::{html, Markup, Render};
use serde::Serialize;
use uuid::Uuid;

pub struct AccountDropdown {
    pub accounts: Vec<crate::orm::accounts::Model>,
    pub primary_account: crate::orm::accounts::Model,
    pub current_path: String,
}

impl AccountDropdown {
    pub fn new(
        accounts: Vec<crate::orm::accounts::Model>,
        primary_account: crate::orm::accounts::Model,
        current_path: &str,
    ) -> Self {
        Self {
            accounts,
            primary_account,
            current_path: current_path.to_string(),
        }
    }
}

#[derive(Serialize)]
struct SetPrimaryParams<'a> {
    account_id: &'a Uuid,
    redirect: &'a str,
}

impl Render for AccountDropdown {
    fn render(&self) -> Markup {
        html! {
            // CSS-only dropdown using the details/summary elements
            details class="relative inline-block text-left" {
                summary class="inline-flex justify-center w-full px-3 sm:px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 border border-indigo-300 rounded-md shadow-sm hover:bg-indigo-100 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 cursor-pointer" {
                    // Show current primary account handle
                    span class="flex items-center gap-1 sm:gap-2" {
                        // Display name/handle with a dropdown arrow
                        span class="text-sm sm:text-md font-medium max-w-[120px] sm:max-w-[180px] truncate" {
                            @if let Some(display_name) = &self.primary_account.display_name {
                                "@" (display_name)
                            } @else {
                                "Account"
                            }
                        }

                        // Dropdown arrow icon - shows a double-arrow icon that works both ways
                        svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 ml-1 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" {
                            path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 10l5-5 5 5M7 14l5 5 5-5" {}
                        }
                    }
                }

                // Dropdown content - appears from bottom in the footer
                div class="origin-bottom-right absolute right-0 bottom-full mb-2 w-[calc(100vw-2rem)] sm:w-64 max-w-[320px] rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 focus:outline-none z-10 divide-y divide-gray-100" {
                    // Fixed position to avoid layout shifts with view-transitions
                    div class="py-1" {
                        // Account list section
                        div class="px-4 py-2 text-xs text-gray-500 uppercase tracking-wider" { "Your Accounts" }

                        @for account in &self.accounts {
                            @let is_current = account.account_id == self.primary_account.account_id;

                            // For each account, show a menu item
                            @let params = SetPrimaryParams {
                                account_id: &account.account_id,
                                redirect: &self.current_path,
                            };
                            @let query_string = serde_urlencoded::to_string(&params).unwrap();
                            a href={"/oauth/bsky/set-primary?" (query_string)}
                              class="flex items-center px-3 sm:px-4 py-2 text-sm hover:bg-gray-100 transition-colors duration-150" {

                                // Show a checkmark for currently active account
                                div class="w-5 text-indigo-600 mr-2 sm:mr-3 flex-shrink-0" {
                                    @if is_current {
                                        svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" {
                                            path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" {}
                                        }
                                    }
                                }

                                // Account information
                                div class="min-w-0 flex-1" {
                                    div class="font-medium truncate" {
                                        @if let Some(display_name) = &account.display_name {
                                            (display_name)
                                        } @else {
                                            "did:" (account.did)
                                        }

                                        @if let Some(handle) = &account.handle {
                                            div class="text-sm text-gray-500" { "@" (handle) }
                                        }
                                    }
                                    @if is_current {
                                        div class="text-xs text-indigo-600" { "Currently active" }
                                    }
                                }
                            }
                        }
                    }

                    // Actions section
                    div class="py-1" {
                        // Add new account option
                        a href="/login" class="flex items-center px-3 sm:px-4 py-2 text-sm text-indigo-700 hover:bg-indigo-50 transition-colors duration-150" {
                            // Plus icon
                            div class="w-5 text-indigo-600 mr-2 sm:mr-3 flex-shrink-0" {
                                svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" {
                                    path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd" {}
                                }
                            }
                            span { "Link new account" }
                        }

                        // Logout option
                        a href="/logout" class="flex items-center px-3 sm:px-4 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors duration-150" {
                            // Logout icon
                            div class="w-5 text-red-600 mr-2 sm:mr-3 flex-shrink-0" {
                                svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" {
                                    path fill-rule="evenodd" d="M3 3a1 1 0 00-1 1v12a1 1 0 001 1h12a1 1 0 001-1V7.414l-1.707-1.707A1 1 0 0014 5.414V4a1 1 0 00-1-1H3zm11.293 1.293a1 1 0 00-1.414 0L11 6.586V14h4v-7.414l-1.707-1.707zM10 14V7a1 1 0 00-1-1H5a1 1 0 00-1 1v7h6zm-6 4a3 3 0 103-3H3v3z" clip-rule="evenodd" {}
                                }
                            }
                            span { "Logout" }
                        }
                    }
                }
            }
        }
    }
}
