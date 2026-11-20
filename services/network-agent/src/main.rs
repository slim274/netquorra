use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use network_engine::scan_network_detailed;
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, sync::Arc};

const AGENT_ADDRESS: &str = "127.0.0.1:47821";

type AgentState = Arc<String>;

#[derive(Deserialize)]
struct ScanRequest {
    cidr: String,
}

#[derive(Serialize)]
struct ScanResponse {
    status: String,
    network: String,
    discovered_count: usize,
    discovered_devices: Vec<network_engine::DiscoveredDevice>,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "netquorra-network-agent"
    }))
}

async fn scan(
    State(token): State<AgentState>,
    headers: HeaderMap,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ApiError>)> {
    // Authenticate request
    let authorized = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .strip_prefix("Bearer ")
                .map(|provided| provided == token.as_str())
                .unwrap_or(false)
        })
        .unwrap_or(false);

    if !authorized {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "Invalid or missing bearer token".to_string(),
            }),
        ));
    }

    // Validate network range
    let cidr = request.cidr.trim();

    if cidr.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "Network range is required".to_string(),
            }),
        ));
    }

    // Perform detailed network discovery
    let discovered_devices = scan_network_detailed(cidr).await.map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: error.to_string(),
            }),
        )
    })?;

    let discovered_count = discovered_devices.len();

    Ok(Json(ScanResponse {
        status: "completed".to_string(),
        network: cidr.to_string(),
        discovered_count,
        discovered_devices,
    }))
}

#[tokio::main]
async fn main() {
    let token =
        env::var("NETQUORRA_AGENT_TOKEN").expect("NETQUORRA_AGENT_TOKEN must be configured");

    if token.len() < 32 {
        panic!("NETQUORRA_AGENT_TOKEN must contain at least 32 characters");
    }

    let state = Arc::new(token);

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/discovery/scan", post(scan))
        .with_state(state);

    let address: SocketAddr = AGENT_ADDRESS.parse().unwrap();

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("Failed to bind Network Agent");

    println!("Netquorra Network Agent listening on {address}");

    axum::serve(listener, app)
        .await
        .expect("Network Agent server failed");
}
