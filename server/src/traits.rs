pub trait IsExpired {
    fn is_expired(&self) -> bool;
}

impl IsExpired for crate::orm::oauth_tokens::Model {
    fn is_expired(&self) -> bool {
        // THis needs to be ripped out, we shouldn't be using these tokens
        todo!()
    }
}

impl IsExpired for crate::orm::sessions::Model {
    fn is_expired(&self) -> bool {
        self.expires_at < chrono::Utc::now()
    }
}
