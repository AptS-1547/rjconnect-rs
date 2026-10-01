//! Strict, allocation-conscious codecs for Ethernet, EAPOL, and EAP.
//!
//! Parsers borrow input bytes, validate every declared length, and preserve
//! unknown protocol values so callers can diagnose forward-compatible frames.

#![forbid(unsafe_code)]

mod eap;
mod eapol;
mod error;
mod ethernet;

pub use eap::{EapCode, EapMethod, EapPacket};
pub use eapol::{EapolPacket, EapolPacketType};
pub use error::{CodecError, Result};
pub use ethernet::{EthernetFrame, MacAddress, VlanTag};

/// `EtherType` assigned to IEEE 802.1X EAPOL.
pub const ETHERTYPE_EAPOL: u16 = 0x888e;
