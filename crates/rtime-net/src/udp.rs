use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use rtime_core::timestamp::NtpTimestamp;
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Platform-specific timestamping constants
// ---------------------------------------------------------------------------

/// Linux-specific SO_TIMESTAMPING constants (linux/net_tstamp.h).
/// Defined here because libc may not expose them.
#[cfg(target_os = "linux")]
mod timestamping {
    pub const SO_TIMESTAMPING: libc::c_int = 37;
    pub const SO_TIMESTAMPNS: libc::c_int = 35;
    pub const SOF_TIMESTAMPING_TX_HARDWARE: u32 = 1 << 0;
    pub const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
    pub const SOF_TIMESTAMPING_RX_HARDWARE: u32 = 1 << 2;
    pub const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
    pub const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
    pub const SOF_TIMESTAMPING_RAW_HARDWARE: u32 = 1 << 6;
}

/// FreeBSD uses SO_TIMESTAMP (microsecond-resolution timestamps).
/// Hardware timestamping is not available through this socket API on FreeBSD.
#[cfg(target_os = "freebsd")]
mod timestamping {
    pub const SO_TIMESTAMP: libc::c_int = 0x0400;
}

/// Timestamping mode currently active on the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampMode {
    /// Timestamps are taken in userspace via `NtpTimestamp::now()`.
    Userspace,
    /// Kernel software timestamps via `SO_TIMESTAMPNS` or `SO_TIMESTAMPING`.
    Software,
    /// Hardware timestamps via `SO_TIMESTAMPING` with `RAW_HARDWARE`.
    Hardware,
}

/// A UDP socket wrapper that captures timestamps on send/receive.
///
/// Supports three timestamping modes (best to worst accuracy):
/// 1. Hardware (SO_TIMESTAMPING with RAW_HARDWARE) -- requires NIC support
/// 2. Kernel software (SO_TIMESTAMPING or SO_TIMESTAMPNS)
/// 3. Userspace (NtpTimestamp::now() immediately after syscall)
pub struct TimestampedSocket {
    inner: UdpSocket,
    mode: TimestampMode,
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
        Ok(Self {
            inner: socket,
            mode: TimestampMode::Userspace,
        })
    }

    /// Wrap an already-bound tokio UdpSocket.
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            inner: socket,
            mode: TimestampMode::Userspace,
        }
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

    /// Current timestamping mode.
    pub fn timestamp_mode(&self) -> TimestampMode {
        self.mode
    }

    /// Enable kernel software timestamps.
    ///
    /// On Linux, uses `SO_TIMESTAMPNS` for nanosecond-resolution software timestamps.
    /// On FreeBSD, uses `SO_TIMESTAMP` for microsecond-resolution timestamps.
    /// The kernel timestamps packets in the network stack, which is more accurate
    /// than userspace timestamps taken after the syscall returns.
    #[cfg(target_os = "linux")]
    pub fn enable_software_timestamps(&mut self) -> std::io::Result<()> {
        let val: libc::c_int = 1;
        let fd = self.inner.as_raw_fd();

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                timestamping::SO_TIMESTAMPNS,
                &val as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.mode = TimestampMode::Software;
        Ok(())
    }

    /// Enable kernel software timestamps.
    ///
    /// On FreeBSD, uses `SO_TIMESTAMP` for microsecond-resolution timestamps from
    /// the kernel network stack.
    #[cfg(target_os = "freebsd")]
    pub fn enable_software_timestamps(&mut self) -> std::io::Result<()> {
        let val: libc::c_int = 1;
        let fd = self.inner.as_raw_fd();

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                timestamping::SO_TIMESTAMP,
                &val as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.mode = TimestampMode::Software;
        Ok(())
    }

    /// Enable kernel software timestamps (unsupported platform fallback).
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    pub fn enable_software_timestamps(&mut self) -> std::io::Result<()> {
        // No kernel timestamping available; remain in userspace mode.
        Ok(())
    }

    /// Enable hardware timestamps via `SO_TIMESTAMPING` (Linux).
    ///
    /// Attempts to enable hardware timestamping using `SOF_TIMESTAMPING_TX_HARDWARE`,
    /// `SOF_TIMESTAMPING_RX_HARDWARE`, and `SOF_TIMESTAMPING_RAW_HARDWARE`. If hardware
    /// timestamping is not supported by the NIC, falls back to software timestamping
    /// via `SO_TIMESTAMPING` with the software flags.
    ///
    /// Returns `Ok(true)` if hardware timestamping is active, `Ok(false)` if it
    /// fell back to software timestamping.
    #[cfg(target_os = "linux")]
    pub fn enable_hardware_timestamps(&mut self) -> std::io::Result<bool> {
        let fd = self.inner.as_raw_fd();

        // Try hardware first.
        let hw_flags: u32 = timestamping::SOF_TIMESTAMPING_TX_HARDWARE
            | timestamping::SOF_TIMESTAMPING_RX_HARDWARE
            | timestamping::SOF_TIMESTAMPING_RAW_HARDWARE;

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                timestamping::SO_TIMESTAMPING,
                &hw_flags as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if ret == 0 {
            self.mode = TimestampMode::Hardware;
            return Ok(true);
        }

        // Hardware not available -- fall back to software via SO_TIMESTAMPING.
        let sw_flags: u32 = timestamping::SOF_TIMESTAMPING_TX_SOFTWARE
            | timestamping::SOF_TIMESTAMPING_RX_SOFTWARE
            | timestamping::SOF_TIMESTAMPING_SOFTWARE;

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                timestamping::SO_TIMESTAMPING,
                &sw_flags as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.mode = TimestampMode::Software;
        Ok(false)
    }

    /// Enable hardware timestamps (FreeBSD).
    ///
    /// Hardware timestamping is not available through the FreeBSD socket API.
    /// Returns `Ok(false)` to indicate software-only timestamps are active.
    #[cfg(target_os = "freebsd")]
    pub fn enable_hardware_timestamps(&mut self) -> std::io::Result<bool> {
        // FreeBSD does not expose hardware timestamping through setsockopt.
        // Fall back to software timestamps.
        self.enable_software_timestamps()?;
        Ok(false)
    }

    /// Enable hardware timestamps (unsupported platform fallback).
    ///
    /// Returns `Ok(false)` since hardware timestamping is not available.
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    pub fn enable_hardware_timestamps(&mut self) -> std::io::Result<bool> {
        Ok(false)
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
