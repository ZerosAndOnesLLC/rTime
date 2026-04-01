use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use tokio::sync::{RwLock, mpsc, watch};
use tracing::{error, info, warn};

use rtime_clock::unix::UnixClock;
use rtime_core::clock::Clock;
use rtime_core::config::RtimeConfig;
use rtime_core::selection::select_sources;
use rtime_core::servo::ServoConfig;
use rtime_core::source::{SourceId, SourceMeasurement};
use rtime_core::timestamp::NtpDuration;
use rtime_metrics::instruments;
use rtime_ntp::server::ServerState;

use crate::clock_discipline;
use crate::management::{self, DaemonStatus, SourceStatus};
use crate::ntp_client;
use crate::ntp_server;
use crate::ptp_node;

/// Channel buffer size for source measurements.
const MEASUREMENT_CHANNEL_SIZE: usize = 64;

/// Default poll interval in seconds (matches NTP client normal poll).
const DEFAULT_POLL_INTERVAL_SECS: f64 = 64.0;

/// The daemon orchestrator. Spawns and manages NTP client tasks, the NTP server,
/// the source selection loop, and the clock discipline task.
pub struct Daemon {
    config: Arc<RtimeConfig>,
    measurement_tx: Option<mpsc::Sender<SourceMeasurement>>,
    measurement_rx: mpsc::Receiver<SourceMeasurement>,
    offset_tx: watch::Sender<Option<NtpDuration>>,
    offset_rx: watch::Receiver<Option<NtpDuration>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    daemon_status: Arc<RwLock<DaemonStatus>>,
    /// Shared readiness flag: set to true after the first successful source selection.
    ready: Arc<AtomicBool>,
}

impl Daemon {
    pub fn new(config: RtimeConfig) -> Self {
        let (measurement_tx, measurement_rx) = mpsc::channel(MEASUREMENT_CHANNEL_SIZE);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (offset_tx, offset_rx) = watch::channel(None);

        Self {
            config: Arc::new(config),
            measurement_tx: Some(measurement_tx),
            measurement_rx,
            offset_tx,
            offset_rx,
            shutdown_tx,
            shutdown_rx,
            daemon_status: Arc::new(RwLock::new(DaemonStatus::new())),
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Run the daemon. This is the main entry point that spawns all tasks
    /// and waits for shutdown.
    pub async fn run(&mut self) -> Result<()> {
        info!("rTime daemon starting");

        let start_time = tokio::time::Instant::now();

        // Spawn metrics exporter if enabled.
        let metrics_handle = if self.config.metrics.enabled {
            let metrics_addr: SocketAddr = self
                .config
                .metrics
                .listen
                .parse()
                .context(format!(
                    "invalid metrics listen address: {}",
                    self.config.metrics.listen
                ))?;

            let exporter = rtime_metrics::exporter::MetricsExporter::new(Arc::clone(&self.ready));

            let handle = tokio::spawn(async move {
                if let Err(e) = exporter.serve(metrics_addr).await {
                    error!("Metrics server exited with error: {}", e);
                }
            });

            info!("Metrics exporter enabled on {}", self.config.metrics.listen);
            Some(handle)
        } else {
            info!("Metrics exporter disabled");
            None
        };

        // Spawn uptime recording task if metrics are enabled.
        let uptime_handle = if self.config.metrics.enabled {
            let shutdown = self.shutdown_rx.clone();
            let handle = tokio::spawn(async move {
                let mut shutdown = shutdown;
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            instruments::record_uptime(start_time.elapsed().as_secs_f64());
                        }
                        result = shutdown.changed() => {
                            if result.is_ok() && *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
            });
            Some(handle)
        } else {
            None
        };

        // Spawn management API if enabled.
        let management_handle = if self.config.management.enabled {
            let mgmt_addr: SocketAddr = self
                .config
                .management
                .listen
                .parse()
                .context(format!(
                    "invalid management listen address: {}",
                    self.config.management.listen
                ))?;

            let status = Arc::clone(&self.daemon_status);
            let router = management::management_router(status);
            let listener = tokio::net::TcpListener::bind(mgmt_addr)
                .await
                .context(format!("failed to bind management API on {}", mgmt_addr))?;

            let handle = tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, router).await {
                    error!("Management API exited with error: {}", e);
                }
            });

            info!("Management API enabled on {}", self.config.management.listen);
            Some(handle)
        } else {
            info!("Management API disabled");
            None
        };

        // Shared server state, updated by the selection task.
        let server_state = Arc::new(RwLock::new(ServerState::default()));

        // Spawn NTP client tasks for each configured source.
        let mut client_handles = Vec::new();
        for source in &self.config.ntp.sources {
            let addr = resolve_source_addr(&source.address)
                .context(format!("failed to resolve NTP source: {}", source.address))?;

            info!("Spawning NTP client for source: {} ({})", source.address, addr);

            let tx = self.measurement_tx.as_ref().expect("measurement_tx taken").clone();
            let shutdown = self.shutdown_rx.clone();
            let metrics_enabled = self.config.metrics.enabled;

            let handle = tokio::spawn(async move {
                if let Err(e) = ntp_client::run_ntp_client(addr, tx, shutdown, metrics_enabled).await {
                    error!("NTP client for {} exited with error: {}", addr, e);
                }
            });

            client_handles.push(handle);
        }

        // Spawn PTP client node task if enabled.
        let ptp_handle = if self.config.ptp.enabled {
            let ptp_config = Arc::new(self.config.ptp.clone());
            let tx = self.measurement_tx.as_ref().expect("measurement_tx taken").clone();
            let shutdown = self.shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = ptp_node::run_ptp_node(ptp_config, tx, shutdown).await {
                    error!("PTP node exited with error: {}", e);
                }
            });

            info!("PTP node enabled (domain={}, interface={})", self.config.ptp.domain, self.config.ptp.interface);
            Some(handle)
        } else {
            info!("PTP node disabled");
            None
        };

        if client_handles.is_empty() && !self.config.ptp.enabled {
            warn!("No NTP sources or PTP configured -- daemon will not synchronize");
        }

        // Spawn NTP server task if enabled.
        let server_handle = if self.config.ntp.enabled {
            let listen_addr: SocketAddr = self
                .config
                .ntp
                .listen
                .parse()
                .context(format!(
                    "invalid NTP listen address: {}",
                    self.config.ntp.listen
                ))?;

            let state = Arc::clone(&server_state);
            let shutdown = self.shutdown_rx.clone();
            let metrics_enabled = self.config.metrics.enabled;

            let handle = tokio::spawn(async move {
                if let Err(e) = ntp_server::run_ntp_server(listen_addr, state, shutdown, metrics_enabled).await {
                    error!("NTP server exited with error: {}", e);
                }
            });

            info!("NTP server enabled on {}", self.config.ntp.listen);
            Some(handle)
        } else {
            info!("NTP server disabled");
            None
        };

        // Spawn clock discipline task if enabled.
        let discipline_handle = if self.config.clock.discipline {
            let clock: Arc<dyn Clock> = Arc::new(UnixClock::new());
            let offset_rx = self.offset_rx.clone();
            let shutdown = self.shutdown_rx.clone();
            let metrics_enabled = self.config.metrics.enabled;

            let servo_config = ServoConfig {
                step_threshold_ns: self.config.clock.step_threshold_ms * 1_000_000.0,
                ..Default::default()
            };

            info!(
                "Clock discipline enabled (adjustable={}, step_threshold={:.0}ms)",
                clock.is_adjustable(),
                self.config.clock.step_threshold_ms,
            );

            let handle = tokio::spawn(async move {
                if let Err(e) = clock_discipline::run_clock_discipline(
                    clock,
                    offset_rx,
                    DEFAULT_POLL_INTERVAL_SECS,
                    servo_config,
                    shutdown,
                    metrics_enabled,
                )
                .await
                {
                    error!("Clock discipline task exited with error: {}", e);
                }
            });

            Some(handle)
        } else {
            info!("Clock discipline disabled (--no-discipline)");
            None
        };

        // Drop our sender so the selection loop can detect
        // when all client tasks have exited (channel closes).
        drop(self.measurement_tx.take());

        // Run the selection loop in the current task.
        let metrics_enabled = self.config.metrics.enabled;
        let daemon_status = Arc::clone(&self.daemon_status);
        let ready = Arc::clone(&self.ready);
        self.run_selection_loop(Arc::clone(&server_state), metrics_enabled, daemon_status, ready)
            .await;

        // Signal shutdown to all tasks.
        let _ = self.shutdown_tx.send(true);

        // Wait for all client tasks to finish.
        for handle in client_handles {
            let _ = handle.await;
        }

        // Wait for server task to finish.
        if let Some(handle) = server_handle {
            let _ = handle.await;
        }

        // Wait for PTP node task to finish.
        if let Some(handle) = ptp_handle {
            let _ = handle.await;
        }

        // Wait for discipline task to finish.
        if let Some(handle) = discipline_handle {
            let _ = handle.await;
        }

        // Wait for metrics tasks to finish.
        if let Some(handle) = metrics_handle {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(handle) = uptime_handle {
            let _ = handle.await;
        }

        // Wait for management API to finish.
        if let Some(handle) = management_handle {
            handle.abort();
            let _ = handle.await;
        }

        info!("rTime daemon stopped");
        Ok(())
    }

    /// The selection loop receives measurements from NTP client tasks,
    /// runs Marzullo's algorithm / source selection, and updates the server state.
    /// When a system offset is computed, it is sent to the clock discipline task.
    async fn run_selection_loop(
        &mut self,
        server_state: Arc<RwLock<ServerState>>,
        metrics_enabled: bool,
        daemon_status: Arc<RwLock<DaemonStatus>>,
        ready: Arc<AtomicBool>,
    ) {
        // Collect recent measurements per source. We keep the latest measurement
        // from each source for the selection algorithm.
        let mut latest_measurements: std::collections::HashMap<
            String,
            SourceMeasurement,
        > = std::collections::HashMap::new();

        let mut shutdown = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                Some(measurement) = self.measurement_rx.recv() => {
                    let source_key = measurement.id.to_string();
                    let offset_ms = measurement.offset.to_millis_f64();
                    let delay_ms = measurement.delay.to_millis_f64();
                    let jitter = measurement.jitter;

                    info!(
                        "Measurement from {}: offset={:+.3}ms delay={:.3}ms jitter={:.3}ms stratum={}",
                        source_key, offset_ms, delay_ms, jitter, measurement.stratum,
                    );

                    latest_measurements.insert(source_key, measurement);

                    // Run source selection on all latest measurements.
                    let measurements: Vec<SourceMeasurement> =
                        latest_measurements.values().cloned().collect();

                    if !measurements.is_empty() {
                        let result = select_sources(&measurements);
                        let sys_offset_ms = result.system_offset.to_millis_f64();

                        info!(
                            "Selection: system_offset={:+.3}ms truechimers={} falsetickers={} jitter={:.3}ms",
                            sys_offset_ms,
                            result.truechimers.len(),
                            result.falsetickers.len(),
                            result.system_jitter * 1000.0,
                        );

                        // Record selection metrics.
                        if metrics_enabled {
                            instruments::record_selection_truechimers(result.truechimers.len());
                            instruments::record_selection_falsetickers(result.falsetickers.len());
                            instruments::record_clock_jitter(result.system_jitter);
                        }

                        if let Some(ref peer_id) = result.system_peer {
                            // Find the measurement for the selected system peer.
                            if let Some(selected) = measurements.iter().find(|m| m.id == *peer_id) {
                                let mut state = server_state.write().await;
                                state.stratum = selected.stratum.saturating_add(1);
                                state.leap_indicator = selected.leap_indicator;
                                state.root_delay = selected.root_delay.to_ntp_short()
                                    + selected.delay.abs().to_ntp_short();
                                state.root_dispersion = selected.root_dispersion.to_ntp_short()
                                    + selected.dispersion.abs().to_ntp_short();
                                state.reference_ts = selected.time;

                                if let SourceId::Ntp { reference_id, .. } = &selected.id {
                                    state.reference_id = *reference_id;
                                }

                                info!(
                                    "Server state updated: stratum={} ref_id=0x{:08x} peer={}",
                                    state.stratum, state.reference_id, peer_id,
                                );

                                // Record clock stratum metric.
                                if metrics_enabled {
                                    instruments::record_clock_stratum(state.stratum);
                                }
                            }

                            // Send system offset to clock discipline task.
                            let _ = self.offset_tx.send(Some(result.system_offset));

                            // Mark daemon as ready after first successful selection.
                            if !ready.load(Ordering::Relaxed) {
                                ready.store(true, Ordering::Relaxed);
                                info!("Daemon ready: first successful source selection complete");
                            }

                            // Record system offset metric.
                            if metrics_enabled {
                                instruments::record_clock_offset(
                                    result.system_offset.to_seconds_f64(),
                                );
                            }
                        } else {
                            warn!(
                                "No system peer selected ({} measurements, {} truechimers)",
                                measurements.len(),
                                result.truechimers.len(),
                            );
                        }

                        // Update management API status.
                        {
                            let mut mgmt = daemon_status.write().await;

                            let synchronized = result.system_peer.is_some();
                            let stratum = if let Some(ref peer_id) = result.system_peer {
                                measurements.iter()
                                    .find(|m| m.id == *peer_id)
                                    .map(|m| m.stratum.saturating_add(1))
                                    .unwrap_or(16)
                            } else {
                                16
                            };

                            mgmt.clock.offset_ms = sys_offset_ms;
                            mgmt.clock.jitter_ms = result.system_jitter * 1000.0;
                            mgmt.clock.stratum = stratum;
                            mgmt.clock.synchronized = synchronized;

                            mgmt.sources = measurements.iter().map(|m| {
                                let selected = result.system_peer.as_ref()
                                    .is_some_and(|peer| *peer == m.id);
                                let reachable = result.truechimers.contains(&m.id);
                                SourceStatus {
                                    id: m.id.to_string(),
                                    offset_ms: m.offset.to_millis_f64(),
                                    delay_ms: m.delay.to_millis_f64(),
                                    jitter_ms: m.jitter * 1000.0,
                                    stratum: m.stratum,
                                    reachable,
                                    selected,
                                }
                            }).collect();
                        }
                    }
                }
                result = shutdown.changed() => {
                    if result.is_ok() && *shutdown.borrow() {
                        info!("Selection loop shutting down");
                        break;
                    }
                }
                else => {
                    // All senders dropped (all clients exited).
                    info!("All NTP client tasks exited, selection loop ending");
                    break;
                }
            }
        }
    }
}

/// Resolve an NTP source address string to a SocketAddr.
/// Supports "host:port" or just "host" (defaults to port 123).
fn resolve_source_addr(address: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;

    let addr_str = if address.contains(':') {
        address.to_string()
    } else {
        format!("{}:123", address)
    };

    addr_str
        .to_socket_addrs()
        .context("failed to resolve address")?
        .next()
        .context("no addresses found")
}
