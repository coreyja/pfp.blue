use axum::{
    extract::State,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use fixtures::{run_server, FixtureArgs, require_env_var};
// Unused imports removed
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tracing::info;

/// PLC Directory fixture server
#[derive(Parser, Debug)]
#[clap(name = "plc-directory-fixture")]
struct Cli {
    #[clap(flatten)]
    common: FixtureArgs,
}

// Server state to hold configured responses
#[derive(Clone)]
struct AppState {
    data: Arc<Mutex<Value>>,
    pds_url: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(Value::Null)),
            pds_url: String::new(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    
    // Get URL of the PDS fixture
    let pds_url = require_env_var("PDS_URL", args.common.force)?;
    
    let mut state = AppState::default();
    state.pds_url = pds_url;

    // Load fixture data if provided
    if let Some(data_path) = &args.common.data {
        if data_path.exists() {
            let data = std::fs::read_to_string(data_path)?;
            let json_data: Value = serde_json::from_str(&data)?;
            *state.data.lock().unwrap() = json_data;
            info!("Loaded fixture data from {}", data_path.display());
        }
    }

    let app = Router::new()
        // PLC Directory endpoints
        .route("/did/:did", get(resolve_did))
        
        .with_state(state);

    run_server(args.common, app).await
}

// Handler implementations

async fn resolve_did(
    State(state): State<AppState>,
    axum::extract::Path(_did): axum::extract::Path<String>
) -> impl IntoResponse {
    // Just respond with our fixture DID doc regardless of the requested DID
    // In a more sophisticated version, we could handle multiple DIDs
    Json(json!({
        "@context": ["https://w3id.org/did/v1"],
        "id": "did:plc:abcdefg",
        "alsoKnownAs": [
            "at://fixture-user.test"
        ],
        "verificationMethod": [
            {
                "id": "did:plc:abcdefg#atproto",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:plc:abcdefg",
                "publicKeyMultibase": "zQYEBzXeuTM9UR3rfvNag6L3RNAs5pQZyYPsomTsgQhsxLdEgCiHgVDHFfv"
            }
        ],
        "service": [
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": state.pds_url
            }
        ]
    }))
}