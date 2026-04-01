//! PTP client node that participates in IEEE 1588 as a slave-only device.
//!
//! Joins the PTP multicast group, listens for Announce/Sync/FollowUp messages,
//! sends DelayReq messages, and feeds SourceMeasurement into the shared selection
//! pipeline alongside NTP sources.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};

use rtime_core::clock::LeapIndicator;
use rtime_core::config::PtpConfig;
use rtime_core::source::{SourceId, SourceMeasurement};
use rtime_core::timestamp::{NtpDuration, NtpTimestamp, PtpTimestamp};
use rtime_net::multicast::{
    PTP_EVENT_PORT, PTP_GENERAL_PORT, PTP_PRIMARY_MULTICAST_V4,
    join_multicast, set_multicast_interface, set_multicast_loopback, set_multicast_ttl,
};
use rtime_ptp::announce::ForeignMasterTable;
use rtime_ptp::delay::E2eDelayState;
use rtime_ptp::message::{
    MessageType, PtpFlags, PtpHeader, PtpMessage, PortIdentity,
};

/// Maximum PTP packet size we expect to receive.
const PTP_MAX_PACKET_SIZE: usize = 1500;

/// Number of jitter samples to keep for RMS calculation.
const JITTER_WINDOW: usize = 8;

/// Default announce interval for the foreign master table (2^1 = 2 seconds).
const DEFAULT_ANNOUNCE_INTERVAL_SECS: f64 = 2.0;

/// Maximum number of foreign masters to track.
const MAX_FOREIGN_MASTERS: usize = 5;

/// Interval between DelayReq messages (seconds).
const DELAY_REQ_INTERVAL_SECS: u64 = 2;

/// Generate a random clock identity from random bytes.
fn generate_clock_identity() -> [u8; 8] {
    let mut id = [0u8; 8];
    // Use a simple approach: take system time nanos + random
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let nanos = now.as_nanos();
    id.copy_from_slice(&nanos.to_le_bytes()[..8]);
    // Mark as locally-administered by setting bit 1 of the first octet
    id[0] |= 0x02;
    id
}

/// Resolve the interface name to an IPv4 address for multicast binding.
/// Falls back to UNSPECIFIED (0.0.0.0) if the interface cannot be resolved.
fn resolve_interface_addr(interface: &str) -> Ipv4Addr {
    // Try to find the interface address via /sys/class/net
    // For simplicity, we'll try to parse it as an IP address first,
    // then fall back to listing interfaces.
    if let Ok(addr) = interface.parse::<Ipv4Addr>() {
        return addr;
    }

    // Try to find the interface by name using getifaddrs
    // For now, fall back to UNSPECIFIED and let the kernel pick.
    warn!(
        "Could not resolve PTP interface '{}' to IPv4 address, using 0.0.0.0",
        interface
    );
    Ipv4Addr::UNSPECIFIED
}

/// Run the PTP client node.
///
/// This task:
/// 1. Joins the PTP multicast group on the configured interface
/// 2. Listens for Announce messages and maintains a foreign master table
/// 3. Listens for Sync/FollowUp messages and records T1/T2
/// 4. Sends DelayReq and processes DelayResp to record T3/T4
/// 5. Computes offset/delay via E2E delay mechanism
/// 6. Sends SourceMeasurement on the shared channel
pub async fn run_ptp_node(
    config: Arc<PtpConfig>,
    measurement_tx: mpsc::Sender<SourceMeasurement>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let interface_addr = resolve_interface_addr(&config.interface);
    let our_identity = generate_clock_identity();
    let our_port = PortIdentity {
        clock_identity: our_identity,
        port_number: 1,
    };

    info!(
        "PTP node starting: domain={}, interface={} ({}), identity={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        config.domain,
        config.interface,
        interface_addr,
        our_identity[0], our_identity[1], our_identity[2], our_identity[3],
        our_identity[4], our_identity[5], our_identity[6], our_identity[7],
    );

    // Bind the event socket (port 319) for Sync/DelayReq/DelayResp.
    let event_socket = UdpSocket::bind(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        PTP_EVENT_PORT,
    ))
    .await
    .context("failed to bind PTP event socket (port 319)")?;

    // Bind the general socket (port 320) for Announce/FollowUp.
    let general_socket = UdpSocket::bind(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        PTP_GENERAL_PORT,
    ))
    .await
    .context("failed to bind PTP general socket (port 320)")?;

    // Join multicast on both sockets.
    join_multicast(&event_socket, PTP_PRIMARY_MULTICAST_V4, interface_addr)
        .context("failed to join PTP multicast on event socket")?;
    join_multicast(&general_socket, PTP_PRIMARY_MULTICAST_V4, interface_addr)
        .context("failed to join PTP multicast on general socket")?;

    // Configure multicast settings on event socket (for sending DelayReq).
    set_multicast_interface(&event_socket, interface_addr)
        .context("failed to set multicast interface on event socket")?;
    set_multicast_loopback(&event_socket, false)
        .context("failed to disable multicast loopback on event socket")?;
    set_multicast_ttl(&event_socket, 1)
        .context("failed to set multicast TTL on event socket")?;

    info!("PTP node: joined multicast group {}", PTP_PRIMARY_MULTICAST_V4);

    let event_socket = Arc::new(event_socket);
    let general_socket = Arc::new(general_socket);

    // Foreign master table for tracking announce messages.
    let mut foreign_masters = ForeignMasterTable::new(DEFAULT_ANNOUNCE_INTERVAL_SECS, MAX_FOREIGN_MASTERS);

    // E2E delay state for collecting timestamps.
    let mut delay_state = E2eDelayState::new();

    // Track the current master we are syncing to.
    let mut current_master: Option<PortIdentity> = None;

    // Sequence ID for DelayReq messages.
    let mut delay_req_seq: u16 = 0;

    // Jitter tracking.
    let mut jitter_samples: Vec<f64> = Vec::new();
    let mut last_offset_ms: Option<f64> = None;

    // Timer for sending DelayReq messages.
    let mut delay_req_interval = tokio::time::interval(Duration::from_secs(DELAY_REQ_INTERVAL_SECS));
    delay_req_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Timer for expiring stale foreign masters.
    let mut expire_interval = tokio::time::interval(Duration::from_secs(10));
    expire_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Track the last Sync sequence ID to correlate with FollowUp.
    let mut pending_sync_seq: Option<u16> = None;
    let mut pending_sync_t2: Option<PtpTimestamp> = None;

    let mut event_buf = [0u8; PTP_MAX_PACKET_SIZE];
    let mut general_buf = [0u8; PTP_MAX_PACKET_SIZE];

    loop {
        tokio::select! {
            // Receive on event socket (Sync, DelayResp).
            result = event_socket.recv_from(&mut event_buf) => {
                match result {
                    Ok((len, from)) => {
                        let recv_time = current_ptp_timestamp();
                        if let Err(e) = handle_event_message(
                            &event_buf[..len],
                            from,
                            recv_time,
                            config.domain,
                            &our_port,
                            &mut delay_state,
                            &mut pending_sync_seq,
                            &mut pending_sync_t2,
                            &mut current_master,
                            &mut jitter_samples,
                            &mut last_offset_ms,
                            &measurement_tx,
                        ).await {
                            debug!("PTP event message error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("PTP event socket recv error: {}", e);
                    }
                }
            }

            // Receive on general socket (Announce, FollowUp).
            result = general_socket.recv_from(&mut general_buf) => {
                match result {
                    Ok((len, from)) => {
                        if let Err(e) = handle_general_message(
                            &general_buf[..len],
                            from,
                            config.domain,
                            &our_port,
                            &mut foreign_masters,
                            &mut delay_state,
                            &mut current_master,
                            &mut pending_sync_seq,
                            &mut pending_sync_t2,
                        ) {
                            debug!("PTP general message error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("PTP general socket recv error: {}", e);
                    }
                }
            }

            // Periodically send DelayReq to current master.
            _ = delay_req_interval.tick() => {
                if let Some(ref _master) = current_master {
                    let t3 = current_ptp_timestamp();
                    if let Err(e) = send_delay_req(
                        &event_socket,
                        config.domain,
                        &our_port,
                        &mut delay_req_seq,
                        t3,
                    ).await {
                        debug!("Failed to send DelayReq: {}", e);
                    } else {
                        delay_state.set_delay_req_departure(t3);
                    }
                }
            }

            // Periodically expire stale foreign masters.
            _ = expire_interval.tick() => {
                foreign_masters.expire_stale(Instant::now());
            }

            // Shutdown signal.
            result = shutdown.changed() => {
                if result.is_ok() && *shutdown.borrow() {
                    info!("PTP node shutting down");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Get the current time as a PtpTimestamp (approximate, from system clock).
fn current_ptp_timestamp() -> PtpTimestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    PtpTimestamp::new(now.as_secs(), now.subsec_nanos())
}

/// Handle a message received on the event socket (Sync, DelayResp).
#[allow(clippy::too_many_arguments)]
async fn handle_event_message(
    data: &[u8],
    _from: SocketAddr,
    recv_time: PtpTimestamp,
    domain: u8,
    our_port: &PortIdentity,
    delay_state: &mut E2eDelayState,
    pending_sync_seq: &mut Option<u16>,
    pending_sync_t2: &mut Option<PtpTimestamp>,
    current_master: &mut Option<PortIdentity>,
    jitter_samples: &mut Vec<f64>,
    last_offset_ms: &mut Option<f64>,
    measurement_tx: &mpsc::Sender<SourceMeasurement>,
) -> Result<()> {
    let msg = PtpMessage::parse(data).context("failed to parse PTP event message")?;
    let header = msg.header();

    // Filter by domain.
    if header.domain_number != domain {
        return Ok(());
    }

    // Ignore our own messages.
    if header.source_port_identity == *our_port {
        return Ok(());
    }

    match msg {
        PtpMessage::Sync { header, origin_timestamp } => {
            // If this Sync is from our current master (or we don't have one yet).
            let master = header.source_port_identity;
            if current_master.is_none() || *current_master == Some(master) {
                // Record T2 (receive time of Sync).
                delay_state.set_sync_arrival(recv_time);

                if header.flags.has(PtpFlags::TWO_STEP) {
                    // Two-step: wait for FollowUp with T1.
                    *pending_sync_seq = Some(header.sequence_id);
                    *pending_sync_t2 = Some(recv_time);
                } else {
                    // One-step: origin_timestamp is T1.
                    delay_state.set_sync_departure(origin_timestamp);
                    *pending_sync_seq = None;
                    *pending_sync_t2 = None;
                }

                debug!(
                    "PTP Sync from {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}: seq={} two_step={}",
                    master.clock_identity[0], master.clock_identity[1],
                    master.clock_identity[2], master.clock_identity[3],
                    master.clock_identity[4], master.clock_identity[5],
                    master.clock_identity[6], master.clock_identity[7],
                    header.sequence_id,
                    header.flags.has(PtpFlags::TWO_STEP),
                );
            }
        }

        PtpMessage::DelayResp { header, receive_timestamp, requesting_port } => {
            // Only process DelayResp addressed to us.
            if requesting_port != *our_port {
                return Ok(());
            }

            // Record T4 (master's receive time of our DelayReq).
            delay_state.set_delay_resp_arrival(receive_timestamp);

            debug!(
                "PTP DelayResp: seq={} T4={}",
                header.sequence_id, receive_timestamp,
            );

            // Try to compute offset/delay if all timestamps collected.
            if let Some((offset, delay)) = delay_state.compute() {
                let offset_ms = offset.to_millis_f64();
                let delay_ms = delay.to_millis_f64();

                info!(
                    "PTP E2E measurement: offset={:+.3}ms delay={:.3}ms",
                    offset_ms, delay_ms,
                );

                // Update jitter estimate.
                let jitter = if let Some(prev) = *last_offset_ms {
                    let diff = offset_ms - prev;
                    jitter_samples.push(diff * diff);
                    if jitter_samples.len() > JITTER_WINDOW {
                        jitter_samples.remove(0);
                    }
                    let sum: f64 = jitter_samples.iter().sum();
                    (sum / jitter_samples.len() as f64).sqrt()
                } else {
                    0.0
                };
                *last_offset_ms = Some(offset_ms);

                // Determine source identity from the master.
                let master_port = current_master.unwrap_or(header.source_port_identity);

                let measurement = SourceMeasurement {
                    id: SourceId::Ptp {
                        clock_identity: master_port.clock_identity,
                        port_number: master_port.port_number,
                    },
                    offset,
                    delay,
                    dispersion: NtpDuration::from_nanos(1_000), // 1us estimated dispersion
                    jitter,
                    stratum: 1, // PTP masters are typically stratum 1
                    leap_indicator: LeapIndicator::NoWarning,
                    root_delay: delay, // approximate
                    root_dispersion: NtpDuration::from_nanos(1_000),
                    time: NtpTimestamp::now(),
                };

                if let Err(e) = measurement_tx.send(measurement).await {
                    warn!("Failed to send PTP measurement: {}", e);
                }

                // Reset for next cycle.
                delay_state.reset();
            }
        }

        _ => {
            // Ignore other event messages (DelayReq, PDelayReq, etc.).
        }
    }

    Ok(())
}

/// Handle a message received on the general socket (Announce, FollowUp).
#[allow(clippy::too_many_arguments)]
fn handle_general_message(
    data: &[u8],
    _from: SocketAddr,
    domain: u8,
    our_port: &PortIdentity,
    foreign_masters: &mut ForeignMasterTable,
    delay_state: &mut E2eDelayState,
    current_master: &mut Option<PortIdentity>,
    pending_sync_seq: &mut Option<u16>,
    _pending_sync_t2: &mut Option<PtpTimestamp>,
) -> Result<()> {
    let msg = PtpMessage::parse(data).context("failed to parse PTP general message")?;
    let header = msg.header();

    // Filter by domain.
    if header.domain_number != domain {
        return Ok(());
    }

    // Ignore our own messages.
    if header.source_port_identity == *our_port {
        return Ok(());
    }

    match msg {
        PtpMessage::Announce { header, announce } => {
            let master = header.source_port_identity;
            let now = Instant::now();

            let qualified = foreign_masters.record_announce(master, announce.clone(), now);

            if qualified {
                // If we don't have a current master, accept the first qualified one.
                // In a more complete implementation, we'd run the BMCA here.
                if current_master.is_none() {
                    *current_master = Some(master);
                    info!(
                        "PTP selected master: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}-{} (GM priority1={} class={})",
                        master.clock_identity[0], master.clock_identity[1],
                        master.clock_identity[2], master.clock_identity[3],
                        master.clock_identity[4], master.clock_identity[5],
                        master.clock_identity[6], master.clock_identity[7],
                        master.port_number,
                        announce.grandmaster_priority1,
                        announce.grandmaster_clock_quality.clock_class,
                    );
                }
            }

            debug!(
                "PTP Announce from {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}: qualified={} steps_removed={}",
                master.clock_identity[0], master.clock_identity[1],
                master.clock_identity[2], master.clock_identity[3],
                master.clock_identity[4], master.clock_identity[5],
                master.clock_identity[6], master.clock_identity[7],
                qualified,
                announce.steps_removed,
            );
        }

        PtpMessage::FollowUp { header, precise_origin_timestamp } => {
            // Match FollowUp to the pending Sync.
            if let Some(sync_seq) = *pending_sync_seq && header.sequence_id == sync_seq {
                // T1 = precise_origin_timestamp from FollowUp.
                delay_state.set_sync_departure(precise_origin_timestamp);
                *pending_sync_seq = None;

                debug!(
                    "PTP FollowUp: seq={} T1={}",
                    header.sequence_id, precise_origin_timestamp,
                );
            }
        }

        _ => {
            // Ignore other general messages.
        }
    }

    Ok(())
}

/// Send a DelayReq message to the PTP multicast group.
async fn send_delay_req(
    event_socket: &UdpSocket,
    domain: u8,
    our_port: &PortIdentity,
    seq: &mut u16,
    t3: PtpTimestamp,
) -> Result<()> {
    let current_seq = *seq;
    *seq = seq.wrapping_add(1);

    let msg = PtpMessage::DelayReq {
        header: PtpHeader::new(MessageType::DelayReq, domain, *our_port, current_seq),
        origin_timestamp: t3,
    };

    let bytes = msg.serialize();
    let dest = SocketAddr::new(PTP_PRIMARY_MULTICAST_V4.into(), PTP_EVENT_PORT);

    event_socket
        .send_to(&bytes, dest)
        .await
        .context("failed to send PTP DelayReq")?;

    debug!("PTP DelayReq sent: seq={}", current_seq);
    Ok(())
}
