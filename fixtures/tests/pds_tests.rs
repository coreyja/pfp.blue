use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::{Child, Command};
use std::time::Duration;
use tokio::time::sleep;

fn start_pds_server(port: u16) -> Child {
    Command::new("cargo")
        .args([
            "run",
            "-p",
            "fixtures",
            "--bin",
            "pds",
            "--",
            "--port",
            &port.to_string(),
        ])
        .spawn()
        .expect("Failed to start PDS server")
}

async fn wait_for_server(port: u16) {
    let client = reqwest::Client::new();
    for _ in 0..60 {
        if client
            .get(format!("http://localhost:{port}/.well-known/jwks.json"))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        sleep(Duration::from_millis(500)).await;
    }
    panic!("Server failed to start on port {port}");
}

#[tokio::test]
async fn test_oauth_protected_resource() {
    let port = 9001;
    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "http://localhost:{port}/.well-known/oauth-protected-resource"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let json: Value = response.json().await.unwrap();
    assert_eq!(
        json["authorization_servers"][0],
        format!("http://localhost:{port}")
    );
    assert_eq!(json["resource"], format!("http://localhost:{port}"));

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}

#[tokio::test]
async fn test_oauth_authorization_server() {
    let port = 9002;
    let client = reqwest::Client::new();

    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    let response = client
        .get(format!(
            "http://localhost:{port}/.well-known/oauth-authorization-server"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let json: Value = response.json().await.unwrap();
    assert_eq!(json["issuer"], format!("http://localhost:{port}"));
    assert_eq!(
        json["token_endpoint"],
        format!("http://localhost:{port}/xrpc/com.atproto.server.getToken")
    );
    assert!(json["scopes_supported"]
        .as_array()
        .unwrap()
        .contains(&json!("atproto")));

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let port = 9003;
    let client = reqwest::Client::new();

    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    let response = client
        .get(format!("http://localhost:{port}/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let json: Value = response.json().await.unwrap();
    assert!(json["keys"].is_array());
    assert_eq!(json["keys"][0]["kid"], "fixture-key-1");
    assert_eq!(json["keys"][0]["alg"], "ES256");

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}

#[tokio::test]
async fn test_oauth_authorization_flow() {
    let port = 9004;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    // Test authorization endpoint with fixture-user.test
    let response = client
        .get(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.authorize"
        ))
        .query(&[
            ("client_id", "did:web:example.com"),
            ("redirect_uri", "http://localhost:3000/oauth/bsky/callback"),
            ("state", "test-state"),
            ("scope", "atproto profile.handle:fixture-user.test"),
            ("response_type", "code"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("http://localhost:3000/oauth/bsky/callback"));
    assert!(location.contains("code="));
    assert!(location.contains("state=test-state"));

    // Extract auth code from redirect URL
    let url = url::Url::parse(location).unwrap();
    let query_params: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let auth_code = query_params.get("code").unwrap();

    // Test token endpoint
    let token_response = client
        .post(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.getToken"
        ))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", auth_code),
            ("client_id", "did:web:example.com"),
            ("redirect_uri", "http://localhost:3000/oauth/bsky/callback"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(token_response.status(), reqwest::StatusCode::OK);

    let token_json: Value = token_response.json().await.unwrap();
    assert!(token_json["access_token"].is_string());
    assert!(token_json["refresh_token"].is_string());
    assert_eq!(token_json["token_type"], "Bearer");
    assert_eq!(token_json["expires_in"], 3600);

    // Validate JWT structure
    let access_token = token_json["access_token"].as_str().unwrap();
    let parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(parts.len(), 3);

    // Decode and validate JWT header
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], "fixture-key-1");

    // Decode and validate JWT payload
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload["iss"], format!("http://localhost:{port}"));
    assert_eq!(payload["sub"], "did:plc:abcdefg");
    assert_eq!(payload["aud"], "did:plc:abcdefg");
    assert!(payload["iat"].is_number());
    assert!(payload["exp"].is_number());
    assert!(payload["scope"].as_str().unwrap().contains("atproto"));

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}

#[tokio::test]
async fn test_oauth_authorization_flow_user2() {
    let port = 9005;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    // Test authorization endpoint with fixture-user2.test
    let response = client
        .get(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.authorize"
        ))
        .query(&[
            ("client_id", "did:web:example.com"),
            ("redirect_uri", "http://localhost:3000/oauth/bsky/callback"),
            ("state", "test-state-2"),
            ("scope", "atproto profile.handle:fixture-user2.test"),
            ("response_type", "code"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::SEE_OTHER);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let url = url::Url::parse(location).unwrap();
    let query_params: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let auth_code = query_params.get("code").unwrap();

    // Test token endpoint for user2
    let token_response = client
        .post(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.getToken"
        ))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", auth_code),
            ("client_id", "did:web:example.com"),
            ("redirect_uri", "http://localhost:3000/oauth/bsky/callback"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(token_response.status(), reqwest::StatusCode::OK);

    let token_json: Value = token_response.json().await.unwrap();

    // Decode and validate JWT payload for user2
    let access_token = token_json["access_token"].as_str().unwrap();
    let parts: Vec<&str> = access_token.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload["sub"], "did:plc:bbbbb");
    assert_eq!(payload["aud"], "did:plc:bbbbb");

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}

#[tokio::test]
async fn test_pushed_authorization_request() {
    let port = 9006;
    let client = reqwest::Client::new();

    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    // Test PAR endpoint
    let par_response = client
        .post(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.pushAuthorization"
        ))
        .form(&[
            ("client_id", "did:web:example.com"),
            ("redirect_uri", "http://localhost:3000/oauth/bsky/callback"),
            ("state", "test-par-state"),
            ("scope", "atproto profile.handle:fixture-user.test"),
            ("code_challenge", "test-challenge"),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(par_response.status(), reqwest::StatusCode::CREATED);

    let par_json: Value = par_response.json().await.unwrap();
    assert!(par_json["request_uri"].is_string());
    assert_eq!(par_json["expires_in"], 60);

    let request_uri = par_json["request_uri"].as_str().unwrap();

    // Use the request_uri in authorization endpoint
    let client_no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let auth_response = client_no_redirect
        .get(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.authorize"
        ))
        .query(&[("request_uri", request_uri)])
        .send()
        .await
        .unwrap();

    assert_eq!(auth_response.status(), reqwest::StatusCode::SEE_OTHER);

    let location = auth_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("http://localhost:3000/oauth/bsky/callback"));
    assert!(location.contains("code="));
    assert!(location.contains("state=test-par-state"));

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}

#[tokio::test]
async fn test_invalid_auth_code() {
    let port = 9007;
    let client = reqwest::Client::new();

    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    // Test token endpoint with invalid auth code
    let token_response = client
        .post(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.getToken"
        ))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "invalid-auth-code"),
            ("client_id", "did:web:example.com"),
            ("redirect_uri", "http://localhost:3000/oauth/bsky/callback"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(token_response.status(), reqwest::StatusCode::BAD_REQUEST);

    let error_json: Value = token_response.json().await.unwrap();
    assert_eq!(error_json["error"], "invalid_grant");

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}

#[tokio::test]
async fn test_missing_auth_code() {
    let port = 9008;
    let client = reqwest::Client::new();

    let mut server = start_pds_server(port);
    wait_for_server(port).await;

    // Test token endpoint without auth code
    let token_response = client
        .post(format!(
            "http://localhost:{port}/xrpc/com.atproto.server.getToken"
        ))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "did:web:example.com"),
            ("redirect_uri", "http://localhost:3000/oauth/bsky/callback"),
        ])
        .send()
        .await
        .unwrap();

    assert_eq!(token_response.status(), reqwest::StatusCode::BAD_REQUEST);

    let error_json: Value = token_response.json().await.unwrap();
    assert_eq!(error_json["error"], "invalid_request");
    assert!(error_json["error_description"]
        .as_str()
        .unwrap()
        .contains("Missing authorization code"));

    // Cleanup
    server.kill().expect("Failed to kill server");
    server.wait().expect("Failed to wait for server");
}
