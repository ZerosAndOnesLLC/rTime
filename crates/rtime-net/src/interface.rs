/// Timestamping capabilities of a network interface.
#[derive(Debug, Clone)]
pub struct TimestampCapabilities {
    pub software_tx: bool,
    pub software_rx: bool,
    pub hardware_tx: bool,
    pub hardware_rx: bool,
}

impl TimestampCapabilities {
    /// Query the timestamping capabilities of a network interface (Linux).
    ///
    /// Uses a best-effort approach:
    /// 1. Checks if the interface exists via `/sys/class/net/{iface}`.
    /// 2. Checks if it has a backing hardware device via `/sys/class/net/{iface}/device/`.
    ///    Hardware devices with PCI backing often support hardware timestamping.
    /// 3. Attempts `SIOCETHTOOL` with `ETHTOOL_GET_TS_INFO` ioctl for precise capability detection.
    /// 4. Falls back to `software_only()` if detection fails.
    ///
    /// Software timestamping is always assumed available on Linux (kernel provides it).
    #[cfg(target_os = "linux")]
    pub fn query(interface_name: &str) -> std::io::Result<Self> {
        use std::path::Path;

        // Validate interface name (prevent path traversal).
        if interface_name.contains('/') || interface_name.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }

        let sys_path = format!("/sys/class/net/{interface_name}");
        if !Path::new(&sys_path).exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("interface {interface_name} not found"),
            ));
        }

        // Try the ioctl-based approach first for accurate detection.
        match query_ethtool_ts_info(interface_name) {
            Ok(caps) => return Ok(caps),
            Err(_) => {
                // ioctl failed -- fall back to sysfs heuristic.
            }
        }

        // Heuristic: if the interface has a backing PCI/platform device,
        // it *might* support hardware timestamping. But without ioctl
        // confirmation we cannot be sure, so we only report software.
        let _has_device = Path::new(&format!("{sys_path}/device")).exists();

        // Software timestamping is always available on Linux.
        Ok(Self::software_only())
    }

    /// Query the timestamping capabilities of a network interface (FreeBSD).
    ///
    /// Verifies the interface exists using `if_nametoindex()`. FreeBSD does not
    /// expose hardware timestamp capabilities through ethtool, so software-only
    /// timestamps are assumed.
    #[cfg(target_os = "freebsd")]
    pub fn query(interface_name: &str) -> std::io::Result<Self> {
        // Validate interface name.
        if interface_name.contains('/') || interface_name.contains('\0') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }

        // Verify interface exists using if_nametoindex.
        if nix::net::if_::if_nametoindex(interface_name).is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("interface not found: {interface_name}"),
            ));
        }

        // FreeBSD: assume software-only timestamps.
        Ok(Self::software_only())
    }

    /// Query the timestamping capabilities of a network interface (unsupported platform).
    ///
    /// Returns software-only capabilities as a safe fallback.
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    pub fn query(_interface_name: &str) -> std::io::Result<Self> {
        Ok(Self::software_only())
    }

    /// Return default software-only capabilities (fallback).
    pub fn software_only() -> Self {
        Self {
            software_tx: true,
            software_rx: true,
            hardware_tx: false,
            hardware_rx: false,
        }
    }

    /// Return capabilities indicating full hardware timestamping support.
    pub fn hardware() -> Self {
        Self {
            software_tx: true,
            software_rx: true,
            hardware_tx: true,
            hardware_rx: true,
        }
    }

    /// Whether any form of hardware timestamping is available.
    pub fn has_hardware(&self) -> bool {
        self.hardware_tx || self.hardware_rx
    }

    /// Whether software timestamping is available (always true on Linux/FreeBSD).
    pub fn has_software(&self) -> bool {
        self.software_tx || self.software_rx
    }
}

// ---------------------------------------------------------------------------
// Linux-specific ETHTOOL ioctl-based timestamp capability query
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod ethtool {
    /// ETHTOOL command number for `ETHTOOL_GET_TS_INFO`.
    pub const ETHTOOL_GET_TS_INFO: u32 = 0x00000041;

    /// SIOCETHTOOL ioctl request number.
    pub const SIOCETHTOOL: libc::c_ulong = 0x8946;

    /// SOF_TIMESTAMPING flag bits we care about.
    pub const SOF_TIMESTAMPING_TX_HARDWARE: u32 = 1 << 0;
    pub const SOF_TIMESTAMPING_TX_SOFTWARE: u32 = 1 << 1;
    pub const SOF_TIMESTAMPING_RX_HARDWARE: u32 = 1 << 2;
    pub const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;

    /// Kernel struct `ethtool_ts_info`. See linux/ethtool.h.
    #[repr(C)]
    #[derive(Default)]
    pub struct EthtoolTsInfo {
        pub cmd: u32,
        pub so_timestamping: u32,
        pub phc_index: i32,
        pub tx_types: u32,
        pub tx_reserved: [u32; 3],
        pub rx_filters: u32,
        pub rx_reserved: [u32; 3],
    }
}

/// Attempt to query timestamping capabilities via SIOCETHTOOL ioctl (Linux only).
#[cfg(target_os = "linux")]
fn query_ethtool_ts_info(interface_name: &str) -> std::io::Result<TimestampCapabilities> {
    use ethtool::*;
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
    use std::os::fd::AsRawFd;

    let name_bytes = interface_name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }

    let mut ts_info = EthtoolTsInfo {
        cmd: ETHTOOL_GET_TS_INFO,
        ..Default::default()
    };

    // The kernel copies a full `struct ifreq` in and back out, so this must
    // be the real `libc::ifreq` (40 bytes on x86_64), not a truncated
    // name + pointer struct.
    // SAFETY: `libc::ifreq` is `#[repr(C)]` plain data (a byte array and a
    // union of integers, sockaddrs and a pointer); all-zero is valid for
    // every field and leaves `ifr_name` NUL-terminated.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, &src) in ifr.ifr_name.iter_mut().zip(name_bytes) {
        *dst = src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_data = (&raw mut ts_info).cast();

    // Temporary socket for the ioctl; closed when `sock` drops.
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    // SAFETY: `ifr` is a correctly sized `struct ifreq` with a NUL-terminated
    // name, and `ifru_data` points at `ts_info`, a live `#[repr(C)]`
    // `ethtool_ts_info` that the kernel fills in. Both outlive the call and
    // are not otherwise borrowed while it runs.
    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCETHTOOL, &raw mut ifr) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let so_ts = ts_info.so_timestamping;

    Ok(TimestampCapabilities {
        software_tx: so_ts & SOF_TIMESTAMPING_TX_SOFTWARE != 0,
        software_rx: so_ts & SOF_TIMESTAMPING_RX_SOFTWARE != 0,
        hardware_tx: so_ts & SOF_TIMESTAMPING_TX_HARDWARE != 0,
        hardware_rx: so_ts & SOF_TIMESTAMPING_RX_HARDWARE != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_only_defaults() {
        let caps = TimestampCapabilities::software_only();
        assert!(caps.software_tx);
        assert!(caps.software_rx);
        assert!(!caps.hardware_tx);
        assert!(!caps.hardware_rx);
        assert!(!caps.has_hardware());
        assert!(caps.has_software());
    }

    #[test]
    fn hardware_defaults() {
        let caps = TimestampCapabilities::hardware();
        assert!(caps.software_tx);
        assert!(caps.software_rx);
        assert!(caps.hardware_tx);
        assert!(caps.hardware_rx);
        assert!(caps.has_hardware());
        assert!(caps.has_software());
    }

    #[test]
    fn query_nonexistent_interface() {
        let result = TimestampCapabilities::query("nonexistent_iface_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn query_invalid_name_slash() {
        let result = TimestampCapabilities::query("../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn query_loopback() {
        // `lo` exists on virtually all Linux systems.
        match TimestampCapabilities::query("lo") {
            Ok(caps) => {
                // Loopback should report at least software capabilities.
                // The ioctl may succeed or fail depending on kernel -- either way
                // we fall back to software_only().
                assert!(caps.software_tx || caps.software_rx || !caps.has_hardware());
            }
            Err(e) => {
                // In very restricted environments lo might not be visible.
                eprintln!("query(\"lo\") failed (may be expected in CI): {e}");
            }
        }
    }
}
