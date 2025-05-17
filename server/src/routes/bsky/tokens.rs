use serde::Deserialize;


#[derive(Deserialize)]
pub struct GetTokenParams {
    /// The DID to get a token for
    pub did: String,
}

#[derive(Deserialize)]
pub struct RevokeTokenParams {
    pub did: String,
}
