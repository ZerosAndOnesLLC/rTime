use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{Router, http::StatusCode, routing::get};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing::info;

/// Prometheus metrics exporter that serves `/metrics`, `/health`, and `/ready` endpoints.
pub struct MetricsExporter {
    handle: PrometheusHandle,
    ready: Arc<AtomicBool>,
}

impl MetricsExporter {
    /// Create a new MetricsExporter and install the Prometheus metrics recorder.
    ///
    /// The `ready` flag should be set to `true` after the daemon has completed
    /// its first successful source selection.
    ///
    /// This must be called before any `metrics::gauge!` / `metrics::counter!` calls
    /// so the global recorder is in place.
    pub fn new(ready: Arc<AtomicBool>) -> Self {
        let builder = PrometheusBuilder::new();
        let handle = builder
            .install_recorder()
            .expect("failed to install metrics recorder");
        Self { handle, ready }
    }

    /// Serve the metrics HTTP endpoint on the given address.
    ///
    /// - `GET /metrics` -- Prometheus scrape endpoint
    /// - `GET /health`  -- liveness probe, always returns 200 "ok"
    /// - `GET /ready`   -- readiness probe, returns 200 if synchronized at least once, 503 otherwise
    pub async fn serve(
        self,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handle = self.handle;
        let ready = self.ready;

        let app = Router::new()
            .route(
                "/metrics",
                get(move || {
                    let h = handle.clone();
                    async move { h.render() }
                }),
            )
            .route("/health", get(|| async { "ok" }))
            .route(
                "/ready",
                get(move || {
                    let r = ready.clone();
                    async move {
                        if r.load(Ordering::Relaxed) {
                            (StatusCode::OK, "ready")
                        } else {
                            (StatusCode::SERVICE_UNAVAILABLE, "not ready")
                        }
                    }
                }),
            );

        info!("Metrics server listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}
