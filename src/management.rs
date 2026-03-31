use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
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

pub fn management_router(status: Arc<RwLock<DaemonStatus>>) -> Router {
    Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/sources", get(get_sources))
        .with_state(status)
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
