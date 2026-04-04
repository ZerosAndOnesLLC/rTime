use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, watch};
use tracing::{debug, info, warn};

use rtime_core::clock::LeapIndicator;
use rtime_core::timestamp::NtpTimestamp;
use rtime_metrics::instruments;
use rtime_ntp::packet::{NTP_HEADER_SIZE, NTP_VERSION, NtpMode, NtpPacket};
use rtime_ntp::server::{ServerState, build_response, validate_request};

// ─── Rate limiter ──────────────────────────────────────────────────────────

/// Per-token-bucket state for rate limiting.
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

/// Maximum number of tracked IPs in the rate limiter to prevent OOM from
/// spoofed source IPs (UDP source addresses are trivially spoofable).
const MAX_RATE_LIMITER_BUCKETS: usize = 100_000;

/// Simple per-IP rate limiter using the token bucket algorithm.
struct RateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    max_rate: f64, // tokens per second
    burst: u32,    // max burst size
}

impl RateLimiter {
    fn new(max_rate: f64, burst: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            max_rate,
            burst,
        }
    }

    /// Returns `true` if the IP has an existing rate-limiter bucket (i.e.,
    /// we have seen at least one successful request from this IP).
    fn is_known(&self, ip: &IpAddr) -> bool {
        self.buckets.contains_key(ip)
    }

    /// Check whether the given IP is allowed to send a request right now.
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let burst = self.burst as f64;
        let max_rate = self.max_rate;

        // Prevent unbounded growth from spoofed source IPs.
        // If we've hit the cap and this is a new IP, rate-limit it.
        if self.buckets.len() >= MAX_RATE_LIMITER_BUCKETS && !self.buckets.contains_key(&ip) {
            return false;
        }

        let bucket = self.buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: burst,
            last_update: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * max_rate).min(burst);
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove stale buckets that have not been updated since `older_than`.
    fn cleanup(&mut self, older_than: Instant) {
        self.buckets.retain(|_, bucket| bucket.last_update > older_than);
    }
}

/// Build a Kiss-o'-Death (KoD) packet with the RATE code.
///
/// Per RFC 5905, a KoD packet has stratum 0 and the reference ID set to
/// an ASCII kiss code (here "RATE").
fn build_kod_rate_response(request: &NtpPacket, receive_ts: NtpTimestamp) -> NtpPacket {
    NtpPacket {
        leap_indicator: LeapIndicator::AlarmUnsynchronized,
        version: NTP_VERSION,
        mode: NtpMode::Server,
        stratum: 0,
        poll: request.poll,
        precision: -20,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: u32::from_be_bytes(*b"RATE"),
        reference_ts: NtpTimestamp::ZERO,
        origin_ts: request.transmit_ts,
        receive_ts,
        transmit_ts: NtpTimestamp::now(),
    }
}

// ─── NTP server ────────────────────────────────────────────────────────────

/// How often to purge stale rate-limiter buckets (seconds).
const CLEANUP_INTERVAL_SECS: u64 = 300;

/// Buckets older than this many seconds are removed during cleanup.
const BUCKET_MAX_AGE_SECS: u64 = 600;

/// Run the async NTP server task.
///
/// Binds a UDP socket on the given listen address and responds to incoming
/// NTP client requests. The server state (stratum, reference info, etc.) is
/// updated by the selection task as clock synchronization progresses.
///
/// Includes per-IP rate limiting: clients that exceed the configured rate
/// receive a KoD (Kiss-o'-Death) response with code "RATE".
///
/// `rate_limit` is the maximum requests per second per IP. `rate_burst` is
/// the token bucket burst size (max tokens accumulated).
///
/// Logs errors on bad packets but does not crash -- resilient to malformed input.
pub async fn run_ntp_server(
    listen_addr: SocketAddr,
    server_state: Arc<RwLock<ServerState>>,
    mut shutdown: watch::Receiver<bool>,
    metrics_enabled: bool,
    rate_limit: f64,
    rate_burst: u32,
) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .context(format!("failed to bind NTP server socket on {}", listen_addr))?;

    info!("NTP server listening on {} (rate_limit={}/s, burst={})", listen_addr, rate_limit, rate_burst);

    let mut buf = [0u8; 512];
    let mut rate_limiter = RateLimiter::new(rate_limit, rate_burst);
    let mut cleanup_interval =
        tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
    // The first tick completes immediately -- consume it.
    cleanup_interval.tick().await;

    loop {
        tokio::select! {
            recv_result = socket.recv_from(&mut buf) => {
                match recv_result {
                    Ok((len, client_addr)) => {
                        // Record receive timestamp as early as possible.
                        let receive_ts = NtpTimestamp::now();

                        // Record incoming packet metric.
                        if metrics_enabled {
                            instruments::increment_ntp_packets_received();
                        }

                        // Per-IP rate limiting check.
                        // Remember whether we've seen this IP before *before*
                        // allow() potentially creates a new bucket for it.
                        let known_ip = rate_limiter.is_known(&client_addr.ip());
                        if !rate_limiter.allow(client_addr.ip()) {
                            debug!("Rate-limiting client {}", client_addr);
                            if metrics_enabled {
                                instruments::increment_ntp_rate_limited();
                            }

                            // Only send KoD RATE to IPs that already had a
                            // bucket (i.e., previously seen clients). Silently
                            // drop packets from unknown IPs to avoid being used
                            // as a reflected amplification vector via spoofed
                            // source addresses.
                            if known_ip
                                && len >= NTP_HEADER_SIZE
                                && let Ok(request) = NtpPacket::parse(&buf[..len])
                            {
                                let kod = build_kod_rate_response(&request, receive_ts);
                                let _ = socket.send_to(&kod.serialize(), client_addr).await;
                            }
                            continue;
                        }

                        match handle_request(
                            &socket,
                            &buf[..len],
                            client_addr,
                            receive_ts,
                            &server_state,
                        ).await {
                            Ok(()) => {
                                // Record outgoing packet metric.
                                if metrics_enabled {
                                    instruments::increment_ntp_packets_sent();
                                }
                            }
                            Err(e) => {
                                debug!("Dropped request from {}: {}", client_addr, e);
                                if metrics_enabled {
                                    instruments::increment_ntp_packets_dropped();
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Log but don't crash on transient socket errors.
                        warn!("NTP server recv error: {}", e);
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                let cutoff = Instant::now() - std::time::Duration::from_secs(BUCKET_MAX_AGE_SECS);
                let before = rate_limiter.buckets.len();
                rate_limiter.cleanup(cutoff);
                let removed = before - rate_limiter.buckets.len();
                if removed > 0 {
                    debug!("Rate limiter cleanup: removed {} stale buckets", removed);
                }
            }
            result = shutdown.changed() => {
                if result.is_ok() && *shutdown.borrow() {
                    info!("NTP server shutting down");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Handle a single incoming NTP request.
async fn handle_request(
    socket: &UdpSocket,
    data: &[u8],
    client_addr: SocketAddr,
    receive_ts: NtpTimestamp,
    server_state: &Arc<RwLock<ServerState>>,
) -> Result<()> {
    if data.len() < NTP_HEADER_SIZE {
        anyhow::bail!("packet too short: {} bytes", data.len());
    }

    let request = NtpPacket::parse(data).context("failed to parse NTP request")?;

    validate_request(&request).context("invalid NTP request")?;

    // Read current server state.
    let state = server_state.read().await;

    // Build response with current transmit timestamp.
    let transmit_ts = NtpTimestamp::now();
    let response = build_response(&request, receive_ts, transmit_ts, &state);

    let response_bytes = response.serialize();
    socket
        .send_to(&response_bytes, client_addr)
        .await
        .context("failed to send NTP response")?;

    debug!(
        "Responded to {} (stratum={}, ref_id=0x{:08x})",
        client_addr, state.stratum, state.reference_id,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_within_burst() {
        let mut rl = RateLimiter::new(10.0, 5);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Should allow up to burst count immediately.
        for _ in 0..5 {
            assert!(rl.allow(ip));
        }
    }

    #[test]
    fn rate_limiter_blocks_after_burst() {
        let mut rl = RateLimiter::new(10.0, 3);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Exhaust burst.
        for _ in 0..3 {
            assert!(rl.allow(ip));
        }

        // Next request should be blocked.
        assert!(!rl.allow(ip));
    }

    #[test]
    fn rate_limiter_independent_ips() {
        let mut rl = RateLimiter::new(10.0, 2);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust ip1 burst.
        assert!(rl.allow(ip1));
        assert!(rl.allow(ip1));
        assert!(!rl.allow(ip1));

        // ip2 should still be allowed.
        assert!(rl.allow(ip2));
    }

    #[test]
    fn rate_limiter_cleanup() {
        let mut rl = RateLimiter::new(10.0, 5);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        rl.allow(ip);
        assert_eq!(rl.buckets.len(), 1);

        // Cleanup with a cutoff in the future should remove the bucket.
        rl.cleanup(Instant::now() + std::time::Duration::from_secs(1));
        assert!(rl.buckets.is_empty());
    }

    #[test]
    fn kod_rate_response_fields() {
        let request = NtpPacket::new_client_request(NtpTimestamp::new(1000, 1));
        let receive_ts = NtpTimestamp::new(1000, 100);
        let kod = build_kod_rate_response(&request, receive_ts);

        assert_eq!(kod.stratum, 0);
        assert_eq!(kod.reference_id, u32::from_be_bytes(*b"RATE"));
        assert_eq!(kod.mode, NtpMode::Server);
        assert_eq!(kod.origin_ts, request.transmit_ts);
        assert_eq!(kod.receive_ts, receive_ts);
    }
}
