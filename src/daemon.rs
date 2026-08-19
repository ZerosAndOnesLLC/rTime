use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use tokio::sync::{RwLock, mpsc, watch};
use tracing::{debug, error, info, warn};

use rtime_clock::unix::UnixClock;
use rtime_core::clock::Clock;
use rtime_core::config::RtimeConfig;
use rtime_core::selection::select_sources;
use rtime_core::servo::ServoConfig;
use rtime_core::source::{SourceId, SourceMeasurement};
use rtime_core::steps::StepLedger;
use rtime_core::timestamp::NtpDuration;
use rtime_metrics::instruments;
use rtime_ntp::server::ServerState;

use crate::clock_discipline::{self, DisciplineExit};
use crate::management::{self, DaemonStatus, SourceStatus};
use crate::measurement::StampedMeasurement;
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
    measurement_tx: Option<mpsc::Sender<StampedMeasurement>>,
    measurement_rx: mpsc::Receiver<StampedMeasurement>,
    offset_tx: watch::Sender<Option<NtpDuration>>,
    offset_rx: watch::Receiver<Option<NtpDuration>>,
    /// Ledger of clock steps applied by the discipline task, consulted by the
    /// selection loop to reconcile measurements taken before a step.
    step_tx: watch::Sender<StepLedger>,
    step_rx: watch::Receiver<StepLedger>,
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
        let (step_tx, step_rx) = watch::channel(StepLedger::new());

        Self {
            config: Arc::new(config),
            measurement_tx: Some(measurement_tx),
            measurement_rx,
            offset_tx,
            offset_rx,
            step_tx,
            step_rx,
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
            let metrics_addr: SocketAddr = self.config.metrics.listen.parse().context(format!(
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

        // Spawn management API if enabled. Bind failures are NOT fatal —
        // NTP is the core service; an auxiliary API should not take it down.
        // See rTime issue #45 — previously this used `?` and a bind-port
        // race caused an infinite process-restart loop via `daemon -R 5`.
        let management_handle = if self.config.management.enabled {
            let mgmt_addr: SocketAddr = self.config.management.listen.parse().context(format!(
                "invalid management listen address: {}",
                self.config.management.listen
            ))?;

            match bind_tcp_reuseaddr(mgmt_addr) {
                Ok(listener) => {
                    let status = Arc::clone(&self.daemon_status);
                    let api_key = self.config.management.api_key.clone();
                    let router = management::management_router(status, api_key);

                    let handle = tokio::spawn(async move {
                        if let Err(e) = axum::serve(listener, router).await {
                            error!("Management API exited with error: {}", e);
                        }
                    });

                    info!(
                        "Management API enabled on {}",
                        self.config.management.listen
                    );
                    Some(handle)
                }
                Err(e) => {
                    warn!(
                        "Management API bind failed on {} ({}); continuing without it",
                        mgmt_addr, e
                    );
                    None
                }
            }
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

            info!(
                "Spawning NTP client for source: {} ({})",
                source.address, addr
            );

            let tx = self
                .measurement_tx
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "measurement_tx already taken before spawning NTP client for {}",
                        source.address
                    )
                })?
                .clone();
            let shutdown = self.shutdown_rx.clone();
            let metrics_enabled = self.config.metrics.enabled;
            let min_poll = source.min_poll;
            let max_poll = source.max_poll;

            let handle = tokio::spawn(async move {
                if let Err(e) = ntp_client::run_ntp_client(
                    addr,
                    tx,
                    shutdown,
                    metrics_enabled,
                    min_poll,
                    max_poll,
                )
                .await
                {
                    error!("NTP client for {} exited with error: {}", addr, e);
                }
            });

            client_handles.push(handle);
        }

        // Spawn PTP client node task if enabled.
        let ptp_handle = if self.config.ptp.enabled {
            let ptp_config = Arc::new(self.config.ptp.clone());
            let tx = self
                .measurement_tx
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!("measurement_tx already taken before spawning PTP node")
                })?
                .clone();
            let shutdown = self.shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = ptp_node::run_ptp_node(ptp_config, tx, shutdown).await {
                    error!("PTP node exited with error: {}", e);
                }
            });

            info!(
                "PTP node enabled (domain={}, interface={})",
                self.config.ptp.domain, self.config.ptp.interface
            );
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
            let listen_addr: SocketAddr = self.config.ntp.listen.parse().context(format!(
                "invalid NTP listen address: {}",
                self.config.ntp.listen
            ))?;

            let state = Arc::clone(&server_state);
            let shutdown = self.shutdown_rx.clone();
            let metrics_enabled = self.config.metrics.enabled;

            let rate_limit = self.config.ntp.rate_limit;
            let rate_burst = self.config.ntp.rate_burst;

            let handle = tokio::spawn(async move {
                if let Err(e) = ntp_server::run_ntp_server(
                    listen_addr,
                    state,
                    shutdown,
                    metrics_enabled,
                    rate_limit,
                    rate_burst,
                )
                .await
                {
                    error!("NTP server exited with error: {}", e);
                }
            });

            info!("NTP server enabled on {}", self.config.ntp.listen);
            Some(handle)
        } else {
            info!("NTP server disabled");
            None
        };

        // Spawn clock discipline task if enabled. If it reports the clock as
        // stranded (panic clamp tripping repeatedly), it requests shutdown and
        // `run` returns an error so the supervisor restarts us with the
        // `allow_initial_step` bypass armed.
        let fatal: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let discipline_handle = if self.config.clock.discipline {
            let clock: Arc<dyn Clock> = Arc::new(UnixClock::new());
            let offset_rx = self.offset_rx.clone();
            let step_tx = self.step_tx.clone();
            let shutdown = self.shutdown_rx.clone();
            let shutdown_tx = self.shutdown_tx.clone();
            let metrics_enabled = self.config.metrics.enabled;
            let panic_restart_after = self.config.clock.panic_restart_after;
            let fatal = Arc::clone(&fatal);

            let servo_config = ServoConfig {
                step_threshold_ns: self.config.clock.step_threshold_ms * 1_000_000.0,
                panic_threshold_ns: self.config.clock.panic_threshold_ms * 1_000_000.0,
                allow_initial_step: self.config.clock.allow_initial_step,
                ..Default::default()
            };

            info!(
                "Clock discipline enabled (adjustable={}, step_threshold={:.0}ms, panic_threshold={:.0}ms, allow_initial_step={}, panic_restart_after={})",
                clock.is_adjustable(),
                self.config.clock.step_threshold_ms,
                self.config.clock.panic_threshold_ms,
                self.config.clock.allow_initial_step,
                panic_restart_after,
            );

            let handle = tokio::spawn(async move {
                let exit = clock_discipline::run_clock_discipline(
                    clock,
                    offset_rx,
                    step_tx,
                    DEFAULT_POLL_INTERVAL_SECS,
                    servo_config,
                    panic_restart_after,
                    shutdown,
                    metrics_enabled,
                )
                .await;
                if let DisciplineExit::PanicStranded {
                    rejects,
                    last_offset_ns,
                } = exit
                {
                    if let Ok(mut slot) = fatal.lock() {
                        *slot = Some(format!(
                            "clock stranded: {} consecutive offsets exceeded the panic \
                             threshold (last {} ns); restarting for allow_initial_step",
                            rejects, last_offset_ns
                        ));
                    }
                    let _ = shutdown_tx.send(true);
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
        self.run_selection_loop(
            Arc::clone(&server_state),
            metrics_enabled,
            daemon_status,
            ready,
        )
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

        let fatal_reason = fatal.lock().ok().and_then(|slot| slot.clone());
        if let Some(reason) = fatal_reason {
            error!("rTime daemon stopping with error: {}", reason);
            bail!(reason);
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
        // from each source for the selection algorithm. Entries are raw as
        // measured; `usable_measurements` reconciles them against the step
        // ledger and expiry at selection time.
        let mut latest_measurements: std::collections::HashMap<String, StampedMeasurement> =
            std::collections::HashMap::new();

        let mut shutdown = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                Some(stamped) = self.measurement_rx.recv() => {
                    let measurement = &stamped.measurement;
                    let source_key = measurement.id.to_string();
                    let offset_ms = measurement.offset.to_millis_f64();
                    let delay_ms = measurement.delay.to_millis_f64();
                    let jitter = measurement.jitter;

                    info!(
                        "Measurement from {}: offset={:+.3}ms delay={:.3}ms jitter={:.3}ms stratum={}",
                        source_key, offset_ms, delay_ms, jitter, measurement.stratum,
                    );

                    latest_measurements.insert(source_key, stamped);

                    // Run source selection on every cached measurement that is
                    // still trustworthy after the clock steps applied since it
                    // was taken.
                    let measurements = usable_measurements(
                        &mut latest_measurements,
                        &self.step_rx.borrow(),
                        Instant::now(),
                    );

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
                                // Reject sources with invalid stratum (valid synced range: 1-15).
                                if selected.stratum == 0 || selected.stratum > 15 {
                                    warn!(
                                        "Ignoring peer {} with invalid stratum {}",
                                        peer_id, selected.stratum,
                                    );
                                    continue;
                                }
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

/// Reconcile the cached per-source measurements with the clock steps applied
/// since each was taken, dropping the ones that can no longer be trusted.
///
/// - Expired entries (source silent for longer than its validity window) are
///   evicted so a dead source cannot keep voting with stale data.
/// - Entries whose exchange straddled a step, or that predate the ledger
///   horizon, are evicted: their offsets mix pre- and post-step timestamps.
/// - Entries taken before a step have the step removed from their offset, so a
///   correction is never re-applied from a stale cache (the doubling failure
///   this guards against is described in [`rtime_core::steps`]).
fn usable_measurements(
    cache: &mut std::collections::HashMap<String, StampedMeasurement>,
    ledger: &StepLedger,
    now: Instant,
) -> Vec<SourceMeasurement> {
    let mut usable = Vec::with_capacity(cache.len());
    cache.retain(|key, stamped| {
        if stamped.is_expired(now) {
            debug!("Dropping expired measurement from {}", key);
            return false;
        }
        match ledger.correct(
            stamped.started_at,
            stamped.finished_at,
            stamped.measurement.offset,
        ) {
            Some(offset) => {
                let mut m = stamped.measurement.clone();
                if offset != m.offset {
                    debug!(
                        "Measurement from {} predates a clock step; offset {} -> {}",
                        key, m.offset, offset
                    );
                    m.offset = offset;
                }
                usable.push(m);
                true
            }
            None => {
                debug!(
                    "Dropping measurement from {}: its exchange overlapped a clock step",
                    key
                );
                false
            }
        }
    });
    usable
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

/// Bind a TCP listener with `SO_REUSEADDR` so a restarted process can reclaim
/// its port immediately instead of racing against TIME_WAIT sockets from the
/// prior instance. See rTime issue #45.
fn bind_tcp_reuseaddr(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use rtime_core::clock::LeapIndicator;
    use rtime_core::timestamp::NtpTimestamp;

    fn ntp_measurement(
        n: u8,
        offset_ms: i64,
        started_at: Instant,
        rtt: Duration,
    ) -> StampedMeasurement {
        StampedMeasurement {
            started_at,
            finished_at: started_at + rtt,
            valid_for: Some(Duration::from_secs(128)),
            measurement: SourceMeasurement {
                id: SourceId::Ntp {
                    address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)), 123),
                    reference_id: u32::from(n),
                },
                offset: NtpDuration::from_millis(offset_ms),
                delay: NtpDuration::from_millis(10),
                dispersion: NtpDuration::from_millis(1),
                jitter: 0.001,
                stratum: 2,
                leap_indicator: LeapIndicator::NoWarning,
                root_delay: NtpDuration::from_millis(5),
                root_dispersion: NtpDuration::from_millis(1),
                time: NtpTimestamp::ZERO,
            },
        }
    }

    fn cache_of(items: Vec<StampedMeasurement>) -> HashMap<String, StampedMeasurement> {
        items
            .into_iter()
            .map(|m| (m.measurement.id.to_string(), m))
            .collect()
    }

    /// The production failure: three sources report +130ms, the servo steps
    /// +130ms on the first selection, then the two cached measurements from
    /// the other sources are re-selected. Before the ledger they re-elected
    /// +130ms and the clock was stepped again (and again), doubling the error
    /// every round. Now they must read ~0 and no further step can result.
    #[test]
    fn stale_cache_is_corrected_after_step() {
        let t0 = Instant::now();
        let rtt = Duration::from_millis(10);
        let mut cache = cache_of(vec![
            ntp_measurement(1, 130, t0, rtt),
            ntp_measurement(2, 131, t0 + Duration::from_millis(1), rtt),
            ntp_measurement(3, 129, t0 + Duration::from_millis(2), rtt),
        ]);

        // Before the step, selection sees the real +130ms consensus.
        let ledger = StepLedger::new();
        let before = usable_measurements(&mut cache, &ledger, t0 + Duration::from_millis(20));
        assert_eq!(before.len(), 3);
        let sel = select_sources(&before);
        assert!((sel.system_offset.to_millis_f64() - 130.0).abs() < 2.0);

        // The discipline task steps the clock by the selected offset.
        let mut ledger = StepLedger::new();
        let step_at = t0 + Duration::from_millis(50);
        ledger.record(
            step_at,
            step_at + Duration::from_micros(30),
            sel.system_offset,
        );

        // Re-running selection over the same cache must now show the residual only.
        let after = usable_measurements(&mut cache, &ledger, t0 + Duration::from_millis(60));
        assert_eq!(
            after.len(),
            3,
            "pre-step measurements stay usable, corrected"
        );
        let sel2 = select_sources(&after);
        assert!(
            sel2.system_offset.to_millis_f64().abs() < 2.0,
            "stale cache must not re-elect the old offset, got {}ms",
            sel2.system_offset.to_millis_f64()
        );
        assert!(
            sel2.system_offset.abs() < NtpDuration::from_millis(128),
            "residual must be below the step threshold so no second step occurs"
        );
    }

    #[test]
    fn measurement_spanning_step_is_evicted() {
        let t0 = Instant::now();
        let mut cache = cache_of(vec![
            ntp_measurement(1, 130, t0, Duration::from_millis(100)), // spans the step
            ntp_measurement(
                2,
                131,
                t0 + Duration::from_millis(200),
                Duration::from_millis(10),
            ),
        ]);
        let mut ledger = StepLedger::new();
        let step_at = t0 + Duration::from_millis(50);
        ledger.record(
            step_at,
            step_at + Duration::from_micros(30),
            NtpDuration::from_millis(130),
        );

        let usable = usable_measurements(&mut cache, &ledger, t0 + Duration::from_millis(300));
        assert_eq!(usable.len(), 1);
        assert_eq!(
            cache.len(),
            1,
            "spanning entry is removed from the cache for good"
        );
        assert!(cache.keys().all(|k| k.ends_with("10.0.0.2:123")));
        // Taken after the step: untouched.
        assert_eq!(usable[0].offset, NtpDuration::from_millis(131));
    }

    #[test]
    fn expired_measurement_is_evicted() {
        let t0 = Instant::now();
        let mut cache = cache_of(vec![
            ntp_measurement(1, 5, t0, Duration::from_millis(10)),
            ntp_measurement(
                2,
                6,
                t0 + Duration::from_secs(100),
                Duration::from_millis(10),
            ),
        ]);
        let ledger = StepLedger::new();
        // 130s later: source 1 (valid for 128s) has gone silent too long.
        let usable = usable_measurements(&mut cache, &ledger, t0 + Duration::from_secs(130));
        assert_eq!(usable.len(), 1);
        assert!(cache.keys().all(|k| k.ends_with("10.0.0.2:123")));
    }
}
