use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

#[derive(Serialize)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: f64,
    pub clock: ClockStatus,
    pub sources: Vec<SourceStatus>,
}

#[derive(Clone, Serialize)]
pub struct ClockStatus {
    pub offset_ms: f64,
    pub jitter_ms: f64,
    pub frequency_ppm: f64,
    pub stratum: u8,
    pub synchronized: bool,
}

impl Default for ClockStatus {
    fn default() -> Self {
        Self {
            offset_ms: 0.0,
            jitter_ms: 0.0,
            frequency_ppm: 0.0,
            stratum: 16,
            synchronized: false,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct SourceStatus {
    pub id: String,
    pub offset_ms: f64,
    pub delay_ms: f64,
    pub jitter_ms: f64,
    pub stratum: u8,
    pub reachable: bool,
    pub selected: bool,
}

/// Shared daemon state accessible by the management API.
pub struct DaemonStatus {
    pub start_time: std::time::Instant,
    pub clock: ClockStatus,
    pub sources: Vec<SourceStatus>,
}

impl DaemonStatus {
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            clock: ClockStatus::default(),
            sources: Vec::new(),
        }
    }
}

pub fn management_router(status: Arc<RwLock<DaemonStatus>>, api_key: Option<String>) -> Router {
    let router = Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/sources", get(get_sources))
        .with_state(status);

    if let Some(key) = api_key {
        let key = Arc::new(key);
        router.layer(middleware::from_fn(move |req, next| {
            let key = Arc::clone(&key);
            auth_middleware(req, next, key)
        }))
    } else {
        router
    }
}

async fn auth_middleware(
    req: Request,
    next: Next,
    api_key: Arc<String>,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = header[7..].as_bytes();
            let expected = api_key.as_bytes();
            // Constant-time comparison to prevent timing side-channel attacks.
            // We first check length equality (which leaks length but not content),
            // then compare bytes in constant time.
            if token.len() == expected.len() && token.ct_eq(expected).into() {
                Ok(next.run(req).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn get_status(
    State(status): State<Arc<RwLock<DaemonStatus>>>,
) -> Json<StatusResponse> {
    let state = status.read().await;
    let uptime = state.start_time.elapsed().as_secs_f64();

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        clock: state.clock.clone(),
        sources: state.sources.clone(),
    })
}

async fn get_sources(
    State(status): State<Arc<RwLock<DaemonStatus>>>,
) -> Json<Vec<SourceStatus>> {
    let state = status.read().await;
    Json(state.sources.clone())
}
