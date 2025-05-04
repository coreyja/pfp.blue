use crate::prelude::*;

pub trait IsExpired {
    fn is_expired(&self) -> bool;
}

impl IsExpired for Session {
    fn is_expired(&self) -> bool {
        self.expires_at < chrono::Utc::now()
    }
}
