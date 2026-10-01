//! Platform capability contracts used by the runtime.
//!
//! The traits expose typed capabilities rather than operating-system handles.
//! Implementations live in target-specific crates.

#![forbid(unsafe_code)]

use std::{net::IpAddr, time::Duration};

use rjconnect_eapol::MacAddress;
use thiserror::Error;

/// Result returned by platform capability implementations.
pub type Result<T> = std::result::Result<T, PlatformError>;

/// Smallest complete Ethernet II frame without its frame check sequence.
pub const MIN_ETHERNET_FRAME_LENGTH: usize = 14;
/// Largest ordinary frame accepted with two VLAN tags and no jumbo support.
pub const MAX_ETHERNET_FRAME_LENGTH: usize = 1522;

/// Stable opaque identifier assigned by a platform adapter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceId(String);

impl InterfaceId {
    /// Creates a non-empty interface identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidInterfaceId`] for an empty value.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            Err(PlatformError::InvalidInterfaceId)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the platform adapter's stable identifier string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Interface category reported by the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    /// Physical or virtual Ethernet interface with a link-layer address.
    Ethernet,
    /// Wi-Fi interface. Client authentication is currently Linux-only.
    Wifi,
    /// Tunnel or VPN interface that may not have a MAC address.
    Tunnel,
    /// Loopback interface.
    Loopback,
    /// Category not recognized by the adapter.
    Other,
}

/// Normalized interface metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Stable platform identifier.
    pub id: InterfaceId,
    /// User-facing name.
    pub display_name: String,
    /// Normalized interface category.
    pub kind: InterfaceKind,
    /// Link-layer address when the interface has one.
    pub mac_address: Option<MacAddress>,
    /// Whether the interface is administratively enabled and link-ready.
    pub is_up: bool,
}

impl InterfaceInfo {
    /// Returns whether the interface can start a wired Ethernet EAPOL session.
    ///
    /// Tunnel interfaces such as Tailscale, `WireGuard`, and generic TUN
    /// devices may be up but legitimately have no link-layer address. They
    /// remain visible for diagnostics but are never treated as usable wired
    /// authentication interfaces.
    #[must_use]
    pub fn supports_wired_eapol(&self) -> bool {
        self.kind == InterfaceKind::Ethernet && self.is_up && self.mac_address.is_some()
    }
}

/// Network parameters assigned by the operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Assigned unicast addresses.
    pub addresses: Vec<IpAddr>,
    /// Current default gateway, if any.
    pub default_gateway: Option<IpAddr>,
    /// Resolver addresses.
    pub dns_servers: Vec<IpAddr>,
}

/// Raw Ethernet channel configuration shared by platform implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameChannelConfig {
    snapshot_length: usize,
    read_timeout: Duration,
    promiscuous: bool,
}

impl FrameChannelConfig {
    /// Smallest snapshot that can carry useful Ethernet control traffic.
    pub const MIN_SNAPSHOT_LENGTH: usize = 64;
    /// Upper boundary accepted by libpcap-compatible capture APIs.
    pub const MAX_SNAPSHOT_LENGTH: usize = 65_535;
    /// Longest read timeout allowed for cooperative worker cancellation.
    pub const MAX_READ_TIMEOUT: Duration = Duration::from_secs(60);
    /// Shortest timeout representable by all selected packet backends.
    pub const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

    /// Creates a validated channel configuration.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when `snapshot_length` is outside
    /// 64..=65,535 or `read_timeout` is zero/longer than 60 seconds.
    pub fn new(snapshot_length: usize, read_timeout: Duration, promiscuous: bool) -> Result<Self> {
        if !(Self::MIN_SNAPSHOT_LENGTH..=Self::MAX_SNAPSHOT_LENGTH).contains(&snapshot_length) {
            return Err(PlatformError::InvalidSnapshotLength {
                actual: snapshot_length,
                minimum: Self::MIN_SNAPSHOT_LENGTH,
                maximum: Self::MAX_SNAPSHOT_LENGTH,
            });
        }
        if read_timeout < Self::MIN_READ_TIMEOUT || read_timeout > Self::MAX_READ_TIMEOUT {
            return Err(PlatformError::InvalidReadTimeout {
                actual: read_timeout,
                minimum: Self::MIN_READ_TIMEOUT,
                maximum: Self::MAX_READ_TIMEOUT,
            });
        }
        Ok(Self {
            snapshot_length,
            read_timeout,
            promiscuous,
        })
    }

    /// Returns the maximum captured bytes per frame.
    #[must_use]
    pub const fn snapshot_length(&self) -> usize {
        self.snapshot_length
    }

    /// Returns the blocking read timeout.
    #[must_use]
    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Returns whether the backend may enable promiscuous capture.
    #[must_use]
    pub const fn promiscuous(&self) -> bool {
        self.promiscuous
    }
}

impl Default for FrameChannelConfig {
    fn default() -> Self {
        Self {
            snapshot_length: 4096,
            read_timeout: Duration::from_millis(250),
            promiscuous: false,
        }
    }
}

/// Result of one bounded blocking receive operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveOutcome {
    /// One complete captured Ethernet frame.
    Frame(Vec<u8>),
    /// No matching frame arrived before the configured read timeout.
    Timeout,
}

impl NetworkConfig {
    /// Returns true when at least one address and a default gateway are ready.
    #[must_use]
    pub const fn is_online_candidate(&self) -> bool {
        !self.addresses.is_empty() && self.default_gateway.is_some()
    }
}

/// Bidirectional raw Ethernet frame channel.
pub trait FrameChannel: Send {
    /// Receives the next complete Ethernet frame or a cooperative timeout.
    ///
    /// # Errors
    ///
    /// Returns a permission, interface-lifecycle, or redacted backend error.
    /// A normal read timeout is returned as [`ReceiveOutcome::Timeout`], not
    /// as an error.
    fn receive(&mut self) -> Result<ReceiveOutcome>;

    /// Sends one complete Ethernet frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the interface disappeared, permission was lost,
    /// or the native backend rejected the complete frame.
    fn send(&mut self, frame: &[u8]) -> Result<()>;
}

/// Platform provider for Ethernet interfaces and frame channels.
pub trait EthernetLink: Send + Sync {
    /// Concrete channel returned by this platform implementation.
    type Channel: FrameChannel;

    /// Lists current interfaces without assuming every interface has a MAC.
    ///
    /// # Errors
    ///
    /// Returns a redacted backend error when the operating system cannot
    /// enumerate interfaces.
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>>;

    /// Opens an interface for EAPOL frame transmission and reception.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable interface, insufficient raw-device
    /// permission, unsupported link type, or native activation failure.
    fn open(&self, interface: &InterfaceId, config: &FrameChannelConfig) -> Result<Self::Channel>;
}

/// Operating-system network configuration owner.
pub trait SystemNetwork: Send + Sync {
    /// Requests the OS to renew or refresh address configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the interface is unavailable or the current
    /// process lacks permission to request a system refresh.
    fn request_address_refresh(&self, interface: &InterfaceId) -> Result<()>;

    /// Waits until the OS reports usable network parameters.
    ///
    /// # Errors
    ///
    /// Returns an error on timeout, interface removal, or backend observation
    /// failure. Implementations must not silently fabricate a gateway or DNS
    /// configuration.
    fn wait_ready(&self, interface: &InterfaceId, timeout: Duration) -> Result<NetworkConfig>;
}

/// Stable platform error category.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// Interface identifier was empty.
    #[error("interface identifier must not be empty")]
    InvalidInterfaceId,
    /// Snapshot length is outside the portable capture boundary.
    #[error("invalid snapshot length {actual}: expected {minimum}..={maximum}")]
    InvalidSnapshotLength {
        /// Invalid requested snapshot length.
        actual: usize,
        /// Minimum accepted byte count.
        minimum: usize,
        /// Maximum accepted byte count.
        maximum: usize,
    },
    /// Read timeout cannot be represented portably or prevents responsive cancellation.
    #[error("invalid read timeout {actual:?}: expected {minimum:?} <= timeout <= {maximum:?}")]
    InvalidReadTimeout {
        /// Invalid requested timeout.
        actual: Duration,
        /// Minimum accepted timeout.
        minimum: Duration,
        /// Maximum accepted timeout.
        maximum: Duration,
    },
    /// Outbound frame is not a complete supported Ethernet II frame.
    #[error("invalid Ethernet frame length {actual}: expected {minimum}..={maximum}")]
    InvalidFrameLength {
        /// Invalid byte count.
        actual: usize,
        /// Minimum complete frame length.
        minimum: usize,
        /// Maximum supported non-jumbo frame length.
        maximum: usize,
    },
    /// Requested capability is not available on this platform or device.
    #[error("unsupported platform capability: {capability}")]
    UnsupportedCapability {
        /// Stable capability name.
        capability: &'static str,
    },
    /// Process lacks permission for raw device access or network control.
    #[error("permission denied while performing {operation}")]
    PermissionDenied {
        /// Stable operation name.
        operation: &'static str,
    },
    /// Interface disappeared or cannot currently be opened.
    #[error("network interface is unavailable: {interface}")]
    InterfaceUnavailable {
        /// Opaque platform identifier.
        interface: String,
    },
    /// Platform backend returned a redacted operational failure.
    #[error("platform operation {operation} failed: {message}")]
    OperationFailed {
        /// Stable operation name.
        operation: &'static str,
        /// Redacted diagnostic message.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_interface_identifier() {
        assert_eq!(InterfaceId::new(""), Err(PlatformError::InvalidInterfaceId));
    }

    #[test]
    fn online_candidate_requires_address_and_gateway() {
        let config = NetworkConfig {
            addresses: vec![IpAddr::from([192, 0, 2, 10])],
            default_gateway: Some(IpAddr::from([192, 0, 2, 1])),
            dns_servers: Vec::new(),
        };

        assert!(config.is_online_candidate());
    }

    #[test]
    fn channel_config_rejects_invalid_snapshot_and_timeout() {
        assert_eq!(
            FrameChannelConfig::new(63, Duration::from_millis(250), false),
            Err(PlatformError::InvalidSnapshotLength {
                actual: 63,
                minimum: FrameChannelConfig::MIN_SNAPSHOT_LENGTH,
                maximum: FrameChannelConfig::MAX_SNAPSHOT_LENGTH,
            })
        );
        assert_eq!(
            FrameChannelConfig::new(4096, Duration::ZERO, false),
            Err(PlatformError::InvalidReadTimeout {
                actual: Duration::ZERO,
                minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
                maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
            })
        );
    }

    #[test]
    fn default_channel_config_is_bounded_and_non_promiscuous() {
        let config = FrameChannelConfig::default();

        assert_eq!(config.snapshot_length(), 4096);
        assert_eq!(config.read_timeout(), Duration::from_millis(250));
        assert!(!config.promiscuous());
    }

    #[test]
    fn tunnel_without_mac_is_visible_but_never_wired_usable() -> Result<()> {
        let tunnel = InterfaceInfo {
            id: InterfaceId::new("tailscale0")?,
            display_name: "Tailscale".to_owned(),
            kind: InterfaceKind::Tunnel,
            mac_address: None,
            is_up: true,
        };
        let ethernet_without_mac = InterfaceInfo {
            id: InterfaceId::new("broken-ethernet")?,
            display_name: "Ethernet without address".to_owned(),
            kind: InterfaceKind::Ethernet,
            mac_address: None,
            is_up: true,
        };
        let ethernet = InterfaceInfo {
            id: InterfaceId::new("en0")?,
            display_name: "USB Ethernet".to_owned(),
            kind: InterfaceKind::Ethernet,
            mac_address: Some(MacAddress::new([2, 3, 4, 5, 6, 7])),
            is_up: true,
        };

        assert!(!tunnel.supports_wired_eapol());
        assert!(!ethernet_without_mac.supports_wired_eapol());
        assert!(ethernet.supports_wired_eapol());
        Ok(())
    }

    #[test]
    fn multiple_usable_ethernet_interfaces_remain_independent_candidates() -> Result<()> {
        let interfaces = [
            InterfaceInfo {
                id: InterfaceId::new("en0")?,
                display_name: "Built-in Ethernet".to_owned(),
                kind: InterfaceKind::Ethernet,
                mac_address: Some(MacAddress::new([2, 0, 0, 0, 0, 1])),
                is_up: true,
            },
            InterfaceInfo {
                id: InterfaceId::new("en5")?,
                display_name: "USB Ethernet".to_owned(),
                kind: InterfaceKind::Ethernet,
                mac_address: Some(MacAddress::new([2, 0, 0, 0, 0, 2])),
                is_up: true,
            },
        ];

        assert!(interfaces.iter().all(InterfaceInfo::supports_wired_eapol));
        assert_ne!(interfaces[0].id, interfaces[1].id);
        Ok(())
    }
}
