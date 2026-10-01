use thiserror::Error;

/// Result type returned by protocol codecs.
pub type Result<T> = std::result::Result<T, CodecError>;

/// A structural error in an Ethernet, EAPOL, or EAP packet.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// The input ended before a complete field could be read.
    #[error("{layer} is truncated: need at least {needed} bytes, got {actual}")]
    Truncated {
        /// Protocol layer being decoded.
        layer: &'static str,
        /// Minimum required byte count.
        needed: usize,
        /// Available byte count.
        actual: usize,
    },

    /// A declared packet length exceeds the containing byte slice.
    #[error("{layer} declares {declared} bytes, but only {available} bytes are available")]
    InvalidLength {
        /// Protocol layer owning the length field.
        layer: &'static str,
        /// Declared byte count.
        declared: usize,
        /// Available byte count.
        available: usize,
    },

    /// A payload cannot be represented by the protocol's 16-bit length field.
    #[error("{layer} payload is too large: {length} bytes")]
    PayloadTooLarge {
        /// Protocol layer being encoded.
        layer: &'static str,
        /// Payload byte count.
        length: usize,
    },

    /// A request or response packet omitted its EAP method byte.
    #[error("EAP request/response packet is missing the method byte")]
    MissingEapMethod,

    /// A terminal EAP packet carried bytes that are forbidden by RFC 3748.
    #[error("EAP success/failure packet must have a declared length of 4, got {length}")]
    InvalidTerminalEapLength {
        /// Invalid declared byte count.
        length: usize,
    },

    /// An Ethernet frame contains more VLAN tags than the supported boundary.
    #[error("Ethernet VLAN nesting exceeds the supported depth of {maximum}")]
    VlanNestingTooDeep {
        /// Maximum supported tag count.
        maximum: usize,
    },

    /// A caller attempted to encode a VLAN tag with a non-VLAN TPID.
    #[error("0x{tpid:04x} is not a supported VLAN TPID")]
    InvalidVlanTpid {
        /// Invalid tag protocol identifier.
        tpid: u16,
    },
}
