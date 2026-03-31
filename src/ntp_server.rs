use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, watch};
use tracing::{debug, info, warn};

use rtime_core::timestamp::NtpTimestamp;
use rtime_ntp::packet::{NTP_HEADER_SIZE, NtpPacket};
use rtime_ntp::server::{ServerState, build_response, validate_request};

/// Run the async NTP server task.
///
/// Binds a UDP socket on the given listen address and responds to incoming
/// NTP client requests. The server state (stratum, reference info, etc.) is
/// updated by the selection task as clock synchronization progresses.
///
/// Logs errors on bad packets but does not crash -- resilient to malformed input.
pub async fn run_ntp_server(
    listen_addr: SocketAddr,
    server_state: Arc<RwLock<ServerState>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .context(format!("failed to bind NTP server socket on {}", listen_addr))?;

    info!("NTP server listening on {}", listen_addr);

    let mut buf = [0u8; 512];

    loop {
        tokio::select! {
            recv_result = socket.recv_from(&mut buf) => {
                match recv_result {
                    Ok((len, client_addr)) => {
                        // Record receive timestamp as early as possible.
                        let receive_ts = NtpTimestamp::now();

                        if let Err(e) = handle_request(
                            &socket,
                            &buf[..len],
                            client_addr,
                            receive_ts,
                            &server_state,
                        ).await {
                            debug!("Dropped request from {}: {}", client_addr, e);
                        }
                    }
                    Err(e) => {
                        // Log but don't crash on transient socket errors.
                        warn!("NTP server recv error: {}", e);
                    }
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
