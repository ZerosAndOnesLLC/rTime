use std::net::SocketAddr;

use axum::{Router, routing::get};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing::info;

/// Prometheus metrics exporter that serves a `/metrics` endpoint
/// and a `/health` endpoint via an HTTP server.
pub struct MetricsExporter {
    handle: PrometheusHandle,
}

impl MetricsExporter {
    /// Create a new MetricsExporter and install the Prometheus metrics recorder.
    ///
    /// This must be called before any `metrics::gauge!` / `metrics::counter!` calls
    /// so the global recorder is in place.
    pub fn new() -> Self {
        let builder = PrometheusBuilder::new();
        let handle = builder
            .install_recorder()
            .expect("failed to install metrics recorder");
        Self { handle }
    }

    /// Serve the metrics HTTP endpoint on the given address.
    ///
    /// - `GET /metrics` -- Prometheus scrape endpoint
    /// - `GET /health`  -- simple health check returning "ok"
    pub async fn serve(
        self,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handle = self.handle;
        let app = Router::new()
            .route(
                "/metrics",
                get(move || {
                    let h = handle.clone();
                    async move { h.render() }
                }),
            )
            .route("/health", get(|| async { "ok" }));

        info!("Metrics server listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}
