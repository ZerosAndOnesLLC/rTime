use std::net::SocketAddr;

use rtime_core::timestamp::NtpTimestamp;
use tokio::net::UdpSocket;

/// A UDP socket wrapper that captures timestamps on send/receive.
///
/// Currently uses software timestamping via `NtpTimestamp::now()`.
/// Hardware timestamping (SO_TIMESTAMPING) will be added in Phase 7.
pub struct TimestampedSocket {
    inner: UdpSocket,
}

/// A received UDP packet with its source address and receive timestamp.
pub struct ReceivedPacket {
    pub data: Vec<u8>,
    pub addr: SocketAddr,
    pub recv_time: NtpTimestamp,
}

impl TimestampedSocket {
    /// Bind to the given address (e.g. "0.0.0.0:123" or "127.0.0.1:0").
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { inner: socket })
    }

    /// Wrap an already-bound tokio UdpSocket.
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self { inner: socket }
    }

    /// Send data to the given address and return the transmit timestamp.
    ///
    /// The timestamp is taken as close to the actual send as possible.
    /// With software timestamping this is immediately after the syscall returns.
    pub async fn send_to(
        &self,
        buf: &[u8],
        addr: SocketAddr,
    ) -> Result<NtpTimestamp, std::io::Error> {
        self.inner.send_to(buf, addr).await?;
        let ts = NtpTimestamp::now();
        Ok(ts)
    }

    /// Receive data into the provided buffer.
    ///
    /// Returns a `ReceivedPacket` containing the data (truncated to actual
    /// received length), the sender's address, and the receive timestamp.
    /// The timestamp is taken as close to the actual receive as possible.
    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<ReceivedPacket, std::io::Error> {
        let (len, addr) = self.inner.recv_from(buf).await?;
        let recv_time = NtpTimestamp::now();
        Ok(ReceivedPacket {
            data: buf[..len].to_vec(),
            addr,
            recv_time,
        })
    }

    /// Get the local address this socket is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.inner.local_addr()
    }

    /// Get a reference to the inner tokio UdpSocket.
    pub fn inner(&self) -> &UdpSocket {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_ephemeral_port() {
        let sock = TimestampedSocket::bind("127.0.0.1:0")
            .await
            .expect("bind should succeed");
        let addr = sock.local_addr().expect("local_addr should succeed");
        assert!(addr.port() > 0, "should have been assigned a port");
        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    }

    #[tokio::test]
    async fn send_recv_loopback() {
        // Bind two sockets on loopback with ephemeral ports
        let sender = TimestampedSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sender");
        let receiver = TimestampedSocket::bind("127.0.0.1:0")
            .await
            .expect("bind receiver");

        let receiver_addr = receiver.local_addr().expect("receiver local_addr");
        let payload = b"NTP test packet data";

        // Send from sender to receiver
        let send_ts = sender
            .send_to(payload, receiver_addr)
            .await
            .expect("send_to");

        // Receive on the receiver side
        let mut buf = [0u8; 1024];
        let received = receiver.recv_from(&mut buf).await.expect("recv_from");

        assert_eq!(received.data, payload);
        assert_eq!(received.addr, sender.local_addr().expect("sender addr"));

        // Timestamps should be non-zero and in reasonable order
        assert_ne!(send_ts, NtpTimestamp::ZERO);
        assert_ne!(received.recv_time, NtpTimestamp::ZERO);
        // recv_time should be >= send_ts (on same machine, software timestamps)
        assert!(
            received.recv_time.raw() >= send_ts.raw(),
            "recv_time ({:?}) should be >= send_ts ({:?})",
            received.recv_time,
            send_ts
        );
    }

    #[tokio::test]
    async fn from_socket_works() {
        let raw = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind raw socket");
        let addr = raw.local_addr().expect("raw local_addr");

        let wrapped = TimestampedSocket::from_socket(raw);
        assert_eq!(
            wrapped.local_addr().expect("wrapped local_addr"),
            addr
        );
    }

    #[tokio::test]
    async fn multiple_packets_loopback() {
        let sender = TimestampedSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sender");
        let receiver = TimestampedSocket::bind("127.0.0.1:0")
            .await
            .expect("bind receiver");

        let receiver_addr = receiver.local_addr().expect("receiver addr");

        // Send multiple packets and verify all arrive
        for i in 0u8..5 {
            let payload = [i; 48]; // NTP-sized packet
            sender
                .send_to(&payload, receiver_addr)
                .await
                .expect("send");

            let mut buf = [0u8; 1024];
            let pkt = receiver.recv_from(&mut buf).await.expect("recv");
            assert_eq!(pkt.data.len(), 48);
            assert_eq!(pkt.data[0], i);
        }
    }
}
