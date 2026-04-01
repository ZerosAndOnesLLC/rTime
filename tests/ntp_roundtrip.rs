//! End-to-end NTP client/server integration tests on loopback.

use rtime_core::clock::LeapIndicator;
use rtime_core::timestamp::NtpTimestamp;
use rtime_ntp::client;
use rtime_ntp::packet::{NtpMode, NtpPacket, NTP_HEADER_SIZE};
use rtime_ntp::server::{build_response, validate_request, ServerState};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Helper: start a minimal NTP server on the given socket that serves responses
/// using the provided ServerState. Returns after processing `max_requests` packets.
async fn serve_ntp(
    socket: Arc<UdpSocket>,
    state: Arc<RwLock<ServerState>>,
    max_requests: usize,
) {
    let mut buf = [0u8; 512];
    for _ in 0..max_requests {
        let (len, client_addr) = socket.recv_from(&mut buf).await.expect("server recv");
        let receive_ts = NtpTimestamp::now();

        if len < NTP_HEADER_SIZE {
            continue;
        }

        let request = match NtpPacket::parse(&buf[..len]) {
            Ok(pkt) => pkt,
            Err(_) => continue,
        };

        if validate_request(&request).is_err() {
            // Send back a simple error or just skip. For the rejection test
            // we just silently drop; the client will time out.
            continue;
        }

        let s = state.read().await;
        let transmit_ts = NtpTimestamp::now();
        let response = build_response(&request, receive_ts, transmit_ts, &s);
        let response_bytes = response.serialize();
        let _ = socket.send_to(&response_bytes, client_addr).await;
    }
}

/// Helper: send a client request and receive a response on the given socket.
async fn query_once(
    socket: &UdpSocket,
    server_addr: std::net::SocketAddr,
) -> client::NtpResult {
    let cookie = NtpTimestamp::now();
    let request = client::build_request(cookie);
    let request_bytes = request.serialize();

    let t1 = NtpTimestamp::now();
    socket
        .send_to(&request_bytes, server_addr)
        .await
        .expect("client send");

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        socket.recv_from(&mut buf),
    )
    .await
    .expect("client recv timeout")
    .expect("client recv");

    let t4 = NtpTimestamp::now();

    let response = NtpPacket::parse(&buf[..len]).expect("parse response");
    client::process_response(&response, t1, t4, cookie).expect("process response")
}

#[tokio::test]
async fn ntp_client_server_roundtrip() {
    // Set up a server on a high ephemeral port.
    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let server_addr = server_socket.local_addr().expect("server addr");
    let server_socket = Arc::new(server_socket);

    let state = Arc::new(RwLock::new(ServerState {
        stratum: 1,
        reference_id: u32::from_be_bytes(*b"GPS\0"),
        reference_ts: NtpTimestamp::now(),
        root_delay: 0,
        root_dispersion: 0x0001_0000,
        leap_indicator: LeapIndicator::NoWarning,
        precision: -20,
    }));

    // Spawn server to handle 1 request.
    let srv_socket = Arc::clone(&server_socket);
    let srv_state = Arc::clone(&state);
    let server_handle = tokio::spawn(async move {
        serve_ntp(srv_socket, srv_state, 1).await;
    });

    // Client query.
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");
    let result = query_once(&client_socket, server_addr).await;

    // Verify the response is sane.
    assert_eq!(result.stratum, 1);
    assert_eq!(result.leap_indicator, LeapIndicator::NoWarning);
    assert_eq!(result.reference_id, u32::from_be_bytes(*b"GPS\0"));

    // On loopback, offset should be very small (within 50ms).
    assert!(
        result.offset.to_millis_f64().abs() < 50.0,
        "offset on loopback should be tiny, got {:.3}ms",
        result.offset.to_millis_f64()
    );

    // Delay should be non-negative and small on loopback.
    assert!(
        result.delay.to_millis_f64() >= 0.0,
        "delay should be non-negative, got {:.3}ms",
        result.delay.to_millis_f64()
    );
    assert!(
        result.delay.to_millis_f64() < 50.0,
        "delay on loopback should be small, got {:.3}ms",
        result.delay.to_millis_f64()
    );

    server_handle.await.expect("server join");
}

#[tokio::test]
async fn multiple_queries_consistent() {
    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let server_addr = server_socket.local_addr().expect("server addr");
    let server_socket = Arc::new(server_socket);

    let state = Arc::new(RwLock::new(ServerState {
        stratum: 2,
        reference_id: u32::from_be_bytes(*b"PPS\0"),
        reference_ts: NtpTimestamp::now(),
        root_delay: 0,
        root_dispersion: 0,
        leap_indicator: LeapIndicator::NoWarning,
        precision: -18,
    }));

    let num_queries = 5;

    // Spawn server to handle multiple requests.
    let srv_socket = Arc::clone(&server_socket);
    let srv_state = Arc::clone(&state);
    let server_handle = tokio::spawn(async move {
        serve_ntp(srv_socket, srv_state, num_queries).await;
    });

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");

    let mut offsets = Vec::new();
    for _ in 0..num_queries {
        let result = query_once(&client_socket, server_addr).await;
        assert_eq!(result.stratum, 2);
        offsets.push(result.offset.to_millis_f64());
    }

    // All offsets on loopback should be close to each other (within 10ms spread).
    let min = offsets.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = offsets.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let spread = max - min;
    assert!(
        spread < 10.0,
        "offsets should be consistent on loopback, spread={:.3}ms, offsets={:?}",
        spread,
        offsets
    );

    server_handle.await.expect("server join");
}

#[tokio::test]
async fn server_rejects_non_client_mode() {
    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let server_addr = server_socket.local_addr().expect("server addr");
    let server_socket = Arc::new(server_socket);

    let state = Arc::new(RwLock::new(ServerState::default()));

    // Spawn server to handle 1 request (but it will be invalid and dropped).
    let srv_socket = Arc::clone(&server_socket);
    let srv_state = Arc::clone(&state);
    let server_handle = tokio::spawn(async move {
        serve_ntp(srv_socket, srv_state, 1).await;
    });

    // Send a packet with Server mode instead of Client mode.
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");

    let mut bad_request = NtpPacket::new_client_request(NtpTimestamp::now());
    bad_request.mode = NtpMode::Server; // wrong mode
    let bytes = bad_request.serialize();

    client_socket
        .send_to(&bytes, server_addr)
        .await
        .expect("send bad request");

    // The server should not respond, so a recv should time out.
    let mut buf = [0u8; 512];
    let result = tokio::time::timeout(
        tokio::time::Duration::from_millis(500),
        client_socket.recv_from(&mut buf),
    )
    .await;

    assert!(
        result.is_err(),
        "server should not respond to non-client mode packets"
    );

    server_handle.await.expect("server join");
}

#[tokio::test]
async fn packet_serialize_roundtrip_on_wire() {
    // Verify that a packet serialized by the client, sent over UDP, and parsed
    // on the server side preserves all fields.
    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let server_addr = server_socket.local_addr().expect("server addr");

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client");

    let original_ts = NtpTimestamp::new(3_900_000_000, 12345);
    let request = NtpPacket::new_client_request(original_ts);
    let bytes = request.serialize();

    client_socket
        .send_to(&bytes, server_addr)
        .await
        .expect("send");

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        tokio::time::Duration::from_secs(1),
        server_socket.recv_from(&mut buf),
    )
    .await
    .expect("recv timeout")
    .expect("recv");

    assert_eq!(len, NTP_HEADER_SIZE);

    let parsed = NtpPacket::parse(&buf[..len]).expect("parse");
    assert_eq!(parsed.mode, NtpMode::Client);
    assert_eq!(parsed.version, 4);
    assert_eq!(parsed.transmit_ts, original_ts);
    assert_eq!(parsed.leap_indicator, LeapIndicator::AlarmUnsynchronized);
}
