// Multicast support for PTP (IEEE 1588).
//
// This module is portable across Unix-like systems (Linux, FreeBSD, macOS).
// All socket options used here (`IP_ADD_MEMBERSHIP`, `IP_DROP_MEMBERSHIP`,
// `IP_MULTICAST_IF`, `IP_MULTICAST_LOOP`, `IP_MULTICAST_TTL`) and the
// `ip_mreq` struct are part of the POSIX/BSD sockets API and are available
// on both Linux and FreeBSD via the `libc` crate.

use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;

use nix::sys::socket::{IpMembershipRequest, setsockopt, sockopt};
use tokio::net::UdpSocket;

/// PTP multicast addresses (IEEE 1588 Annex D).
pub const PTP_PRIMARY_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
pub const PTP_PDELAY_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);

/// PTP UDP port numbers.
pub const PTP_EVENT_PORT: u16 = 319;
pub const PTP_GENERAL_PORT: u16 = 320;

/// Join a multicast group on the given interface.
///
/// Uses `IP_ADD_MEMBERSHIP` via `setsockopt` on the socket's raw file descriptor.
/// The `interface` address specifies which local interface to join on; use
/// `Ipv4Addr::UNSPECIFIED` (0.0.0.0) to let the kernel choose.
pub fn join_multicast(
    socket: &UdpSocket,
    multicast_addr: Ipv4Addr,
    interface: Ipv4Addr,
) -> std::io::Result<()> {
    let interface_opt = if interface.is_unspecified() { None } else { Some(interface) };
    let mreq = IpMembershipRequest::new(multicast_addr, interface_opt);
    setsockopt(socket, sockopt::IpAddMembership, &mreq)
        .map_err(std::io::Error::from)
}

/// Leave a multicast group on the given interface.
///
/// Uses `IP_DROP_MEMBERSHIP` via `setsockopt` on the socket's raw file descriptor.
pub fn leave_multicast(
    socket: &UdpSocket,
    multicast_addr: Ipv4Addr,
    interface: Ipv4Addr,
) -> std::io::Result<()> {
    let interface_opt = if interface.is_unspecified() { None } else { Some(interface) };
    let mreq = IpMembershipRequest::new(multicast_addr, interface_opt);
    setsockopt(socket, sockopt::IpDropMembership, &mreq)
        .map_err(std::io::Error::from)
}

/// Set the outgoing multicast interface for the socket.
///
/// This controls which local interface is used for sending multicast packets.
pub fn set_multicast_interface(
    socket: &UdpSocket,
    interface: Ipv4Addr,
) -> std::io::Result<()> {
    // nix 0.29 does not expose IP_MULTICAST_IF as a typed sockopt; fall back to libc.
    let addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(interface.octets()),
    };

    let fd = socket.as_raw_fd();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MULTICAST_IF,
            &addr as *const libc::in_addr as *const libc::c_void,
            std::mem::size_of::<libc::in_addr>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Disable multicast loopback on the socket.
///
/// When disabled, multicast packets sent on this socket will not be looped back
/// to receivers on the same host. This is typically desired for PTP to avoid
/// processing our own messages.
pub fn set_multicast_loopback(socket: &UdpSocket, enabled: bool) -> std::io::Result<()> {
    setsockopt(socket, sockopt::IpMulticastLoop, &enabled)
        .map_err(std::io::Error::from)
}

/// Set the multicast TTL (time-to-live / hop limit).
///
/// PTP typically uses TTL=1 for link-local multicast (peer delay)
/// and TTL=128 for domain-scoped multicast.
pub fn set_multicast_ttl(socket: &UdpSocket, ttl: u8) -> std::io::Result<()> {
    setsockopt(socket, sockopt::IpMulticastTtl, &ttl)
        .map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_correct() {
        assert_eq!(PTP_PRIMARY_MULTICAST_V4, Ipv4Addr::new(224, 0, 1, 129));
        assert_eq!(PTP_PDELAY_MULTICAST_V4, Ipv4Addr::new(224, 0, 0, 107));
        assert_eq!(PTP_EVENT_PORT, 319);
        assert_eq!(PTP_GENERAL_PORT, 320);
    }

    #[tokio::test]
    async fn join_and_leave_loopback() {
        // Bind to the multicast port on any interface (use ephemeral to avoid permission issues).
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("bind should succeed");

        // Join multicast on loopback -- this may fail in some CI environments
        // but should work on most Linux systems.
        let result = join_multicast(&socket, PTP_PRIMARY_MULTICAST_V4, Ipv4Addr::LOCALHOST);
        if let Err(ref e) = result {
            // ENODEV or similar in CI -- skip gracefully
            eprintln!("join_multicast failed (expected in some CI): {e}");
            return;
        }
        result.unwrap();

        // Leave should succeed after a successful join.
        leave_multicast(&socket, PTP_PRIMARY_MULTICAST_V4, Ipv4Addr::LOCALHOST)
            .expect("leave should succeed after join");
    }

    #[tokio::test]
    async fn set_loopback_and_ttl() {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .expect("bind should succeed");

        set_multicast_loopback(&socket, false).expect("disable loopback");
        set_multicast_loopback(&socket, true).expect("enable loopback");
        set_multicast_ttl(&socket, 1).expect("set ttl=1");
        set_multicast_ttl(&socket, 128).expect("set ttl=128");
    }
}
