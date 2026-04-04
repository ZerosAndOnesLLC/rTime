use std::collections::VecDeque;
use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use rtime_core::source::{SourceId, SourceMeasurement};
use rtime_core::timestamp::NtpTimestamp;
use rtime_metrics::instruments;
use rtime_ntp::client;
use rtime_ntp::packet::{NTP_HEADER_SIZE, NtpPacket};

/// Number of initial burst queries at a fast interval.
const INITIAL_BURST_COUNT: u32 = 4;

/// Interval between initial burst queries (seconds).
const INITIAL_BURST_INTERVAL_SECS: u64 = 8;

/// Socket read timeout (seconds).
const RECV_TIMEOUT_SECS: u64 = 5;

/// Run an async NTP client task that periodically polls an upstream server
/// and sends measurements on the provided channel.
///
/// The task performs an initial burst of fast queries to quickly establish
/// a baseline, then switches to normal polling interval based on `min_poll`
/// (the minimum polling interval as log2 seconds, e.g. 4 = 16s) and
/// `max_poll` (the maximum polling interval as log2 seconds, e.g. 10 = 1024s).
///
/// Currently uses `min_poll` as the normal interval. Adaptive polling between
/// min and max will be implemented in a future phase.
///
/// Respects the shutdown signal and exits cleanly when triggered.
pub async fn run_ntp_client(
    server_addr: SocketAddr,
    measurement_tx: mpsc::Sender<SourceMeasurement>,
    mut shutdown: watch::Receiver<bool>,
    metrics_enabled: bool,
    min_poll: i8,
    max_poll: i8,
) -> Result<()> {
    // Clamp poll values to sane range (2^1 = 2s .. 2^17 = 131072s).
    let min_poll = min_poll.clamp(1, 17);
    let max_poll = max_poll.clamp(min_poll, 17);

    // Use min_poll as the normal interval for now. Adaptive polling between
    // min_poll and max_poll will be implemented in a future phase.
    let normal_poll_secs: u64 = 1u64 << (min_poll as u32);

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind NTP client UDP socket")?;

    info!(
        "NTP client started for {} (poll interval: {}s-{}s)",
        server_addr, 1u64 << (min_poll as u32), 1u64 << (max_poll as u32),
    );

    let mut query_count: u64 = 0;
    let mut jitter_samples: VecDeque<f64> = VecDeque::new();
    let mut last_offset_ms: Option<f64> = None;
    let peer_label = server_addr.to_string();

    loop {
        // Determine poll interval: fast during initial burst, normal after.
        let interval_secs = if query_count < INITIAL_BURST_COUNT as u64 {
            INITIAL_BURST_INTERVAL_SECS
        } else {
            normal_poll_secs
        };

        // Perform a single NTP query.
        match query_server(&socket, server_addr).await {
            Ok(result) => {
                let offset_ms = result.offset.to_millis_f64();
                let delay_ms = result.delay.to_millis_f64();

                debug!(
                    "NTP response from {}: offset={:+.3}ms delay={:.3}ms stratum={}",
                    server_addr, offset_ms, delay_ms, result.stratum,
                );

                // Record packet metrics.
                if metrics_enabled {
                    instruments::increment_ntp_packets_sent();
                    instruments::increment_ntp_packets_received();
                    instruments::record_ntp_source_offset(
                        &peer_label,
                        result.offset.to_seconds_f64(),
                    );
                    instruments::record_ntp_source_delay(
                        &peer_label,
                        result.delay.to_seconds_f64(),
                    );
                }

                // Update jitter estimate (RMS of successive offset differences).
                let jitter = if let Some(prev) = last_offset_ms {
                    let diff = offset_ms - prev;
                    jitter_samples.push_back(diff * diff);
                    // Keep last 8 samples for jitter calculation.
                    if jitter_samples.len() > 8 {
                        jitter_samples.pop_front();
                    }
                    let sum: f64 = jitter_samples.iter().sum();
                    (sum / jitter_samples.len() as f64).sqrt()
                } else {
                    0.0
                };
                last_offset_ms = Some(offset_ms);

                let measurement = SourceMeasurement {
                    id: SourceId::Ntp {
                        address: server_addr,
                        reference_id: result.reference_id,
                    },
                    offset: result.offset,
                    delay: result.delay,
                    dispersion: result.root_dispersion,
                    jitter,
                    stratum: result.stratum,
                    leap_indicator: result.leap_indicator,
                    root_delay: result.root_delay,
                    root_dispersion: result.root_dispersion,
                    time: NtpTimestamp::now(),
                };

                if let Err(e) = measurement_tx.send(measurement).await {
                    warn!("Failed to send measurement (receiver dropped): {}", e);
                    break;
                }

                query_count += 1;
            }
            Err(e) => {
                error!("NTP query to {} failed: {}", server_addr, e);
                // Record a dropped packet on failure.
                if metrics_enabled {
                    instruments::increment_ntp_packets_sent();
                    instruments::increment_ntp_packets_dropped();
                }
            }
        }

        // Wait for the next poll interval, or shutdown.
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)) => {
                // Continue to next poll.
            }
            result = shutdown.changed() => {
                if result.is_ok() && *shutdown.borrow() {
                    info!("NTP client for {} shutting down", server_addr);
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Perform a single async NTP query against the given server.
async fn query_server(
    socket: &UdpSocket,
    addr: SocketAddr,
) -> Result<client::NtpResult> {
    // Use a random-ish cookie (current time) for origin matching.
    let cookie = NtpTimestamp::now();
    let request = client::build_request(cookie);
    let request_bytes = request.serialize();

    // Record T1 just before sending.
    let t1 = NtpTimestamp::now();
    socket
        .send_to(&request_bytes, addr)
        .await
        .context("failed to send NTP request")?;

    // Receive response with timeout.
    let mut buf = [0u8; 512];
    let (len, _from) = tokio::time::timeout(
        tokio::time::Duration::from_secs(RECV_TIMEOUT_SECS),
        socket.recv_from(&mut buf),
    )
    .await
    .context("NTP response timeout")?
    .context("failed to receive NTP response")?;

    // Record T4 immediately after receiving.
    let t4 = NtpTimestamp::now();

    if len < NTP_HEADER_SIZE {
        bail!("NTP response too short: {} bytes", len);
    }

    let response = NtpPacket::parse(&buf[..len]).context("failed to parse NTP response")?;
    let result = client::process_response(&response, t1, t4, cookie)
        .context("failed to process NTP response")?;

    Ok(result)
}
