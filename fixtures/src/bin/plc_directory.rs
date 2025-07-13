use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use clap::Parser;
use fixtures::{require_env_var, run_server, FixtureArgs};
// Unused imports removed
use serde_json::json;

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
    pds_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // Get URL of the PDS fixture
    let pds_url = require_env_var("PDS_URL")?;

    let state = AppState { pds_url };

    let app = Router::new()
        // PLC Directory endpoints - support multiple patterns for DID resolution
        .route("/did/{did}", get(resolve_did))
        // Support exact format that the CommonDidResolver uses
        .route("/{did}", get(resolve_did))
        // Make sure we respond to requests without trailing slash too
        .route("/", get(|| async { "PLC Directory Fixture Server" }))
        // Add catch-all route for all paths to aid debugging
        .fallback(|req: axum::http::Request<axum::body::Body>| async move {
            eprintln!("WARNING: Unhandled request: {} {}", req.method(), req.uri());
            (
                axum::http::StatusCode::NOT_FOUND,
                format!("No route found for {} {}", req.method(), req.uri()),
            )
        })
        .with_state(state);

    run_server(args.common, app).await
}

// Handler implementations

async fn resolve_did(
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> impl IntoResponse {
    println!("PLC DIRECTORY: Resolving DID: {did}");

    // Return different DID documents based on the requested DID
    match did.as_str() {
        "did:plc:bbbbb" => Json(json!({
            "@context": ["https://w3id.org/did/v1"],
            "id": "did:plc:bbbbb",
            "alsoKnownAs": [
                "at://fixture-user2.test"
            ],
            "verificationMethod": [
                {
                    "id": "did:plc:bbbbb#atproto",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": "did:plc:bbbbb",
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
        })),
        _ => {
            // Default to first user's DID document
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
    }
}
