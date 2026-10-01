//! Wired Ethernet frame boundary for an 802.1X session.
//!
//! This crate composes and decomposes complete Ethernet frames while keeping
//! three length domains distinct:
//!
//! 1. EAP length covers the EAP packet only.
//! 2. EAPOL length covers its declared payload only.
//! 3. Recovered Ruijie RADIUS VSAs follow the EAPOL payload as explicit
//!    trailing bytes and are limited by the Ethernet MTU.
//!
//! No device handles or authentication state live here. Platform adapters
//! transport the returned bytes, while `rjconnect-auth` decides what to send.

#![forbid(unsafe_code)]

use rjconnect_eapol::{
    CodecError, ETHERTYPE_EAPOL, EapPacket, EapolPacket, EapolPacketType, EthernetFrame,
    MacAddress, VlanTag,
};
use rjconnect_ruijie::{WiredVendorTrailer, WiredVendorTrailerError};
use thiserror::Error;

/// Maximum Ethernet payload without jumbo-frame negotiation.
pub const MAX_ETHERNET_PAYLOAD_LENGTH: usize = 1500;

/// Result returned by wired frame codecs.
pub type Result<T> = std::result::Result<T, WiredFrameError>;

/// A completely decoded borrowed wired frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundWiredFrame<'a> {
    /// Ethernet destination.
    pub destination: MacAddress,
    /// Ethernet source.
    pub source: MacAddress,
    /// VLAN stack from outermost to innermost.
    pub vlan_tags: Vec<VlanTag>,
    /// Parsed EAPOL packet.
    pub eapol: EapolPacket<'a>,
    /// Parsed EAP packet when the EAPOL type is EAP-Packet.
    pub eap: Option<EapPacket<'a>>,
}

impl<'a> InboundWiredFrame<'a> {
    /// Parses a complete Ethernet frame carrying EAPOL.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed Ethernet/EAPOL/EAP lengths, a non-EAPOL
    /// `EtherType`, or Start/Logoff packets with a declared payload.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        let ethernet = EthernetFrame::parse(input)?;
        if ethernet.ether_type != ETHERTYPE_EAPOL {
            return Err(WiredFrameError::UnexpectedEtherType {
                actual: ethernet.ether_type,
            });
        }
        if ethernet.payload.len() > MAX_ETHERNET_PAYLOAD_LENGTH {
            return Err(WiredFrameError::PayloadTooLarge {
                actual: ethernet.payload.len(),
                maximum: MAX_ETHERNET_PAYLOAD_LENGTH,
            });
        }

        let eapol = EapolPacket::parse(ethernet.payload)?;
        let eap = match eapol.packet_type {
            EapolPacketType::EapPacket => Some(EapPacket::parse(eapol.payload)?),
            EapolPacketType::Start | EapolPacketType::Logoff => {
                if !eapol.payload.is_empty() {
                    return Err(WiredFrameError::UnexpectedControlPayload {
                        packet_type: eapol.packet_type,
                        length: eapol.payload.len(),
                    });
                }
                None
            }
            EapolPacketType::Key
            | EapolPacketType::EncapsulatedAsfAlert
            | EapolPacketType::Unknown(_) => None,
        };

        Ok(Self {
            destination: ethernet.destination,
            source: ethernet.source,
            vlan_tags: ethernet.vlan_tags,
            eapol,
            eap,
        })
    }

    /// Parses the complete trailing wired Ruijie preamble and RADIUS VSAs.
    ///
    /// Ethernet padding and vendor data are indistinguishable at the EAPOL layer.
    /// Call this only after authenticator selection identifies the frame as a
    /// Ruijie vendor frame.
    ///
    /// # Errors
    ///
    /// Returns an error when trailing bytes do not contain the recovered
    /// 70-byte preamble followed by a valid Ruijie VSA stream.
    pub fn ruijie_trailer(
        &self,
    ) -> std::result::Result<WiredVendorTrailer<'a>, WiredVendorTrailerError> {
        WiredVendorTrailer::parse(self.eapol.trailing)
    }
}

/// Encoder configuration shared by one wired session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiredFrameEncoder {
    source: MacAddress,
    destination: MacAddress,
    vlan_tags: Vec<VlanTag>,
    eapol_version: u8,
}

impl WiredFrameEncoder {
    /// Creates an untagged encoder using EAPOL version 1.
    #[must_use]
    pub const fn new(source: MacAddress, destination: MacAddress) -> Self {
        Self {
            source,
            destination,
            vlan_tags: Vec::new(),
            eapol_version: 1,
        }
    }

    /// Replaces the destination selected for subsequent frames.
    pub const fn set_destination(&mut self, destination: MacAddress) {
        self.destination = destination;
    }

    /// Replaces the VLAN stack copied from the authenticated link.
    ///
    /// # Errors
    ///
    /// Returns a codec error when more than two VLAN tags are supplied.
    pub fn set_vlan_tags(&mut self, vlan_tags: Vec<VlanTag>) -> Result<()> {
        if vlan_tags.len() > 2 {
            return Err(WiredFrameError::Codec(CodecError::VlanNestingTooDeep {
                maximum: 2,
            }));
        }
        self.vlan_tags = vlan_tags;
        Ok(())
    }

    /// Encodes EAPOL-Start without a vendor trailer.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured Ethernet envelope is invalid.
    pub fn encode_start(&self) -> Result<Vec<u8>> {
        self.encode(EapolPacketType::Start, &[], &[])
    }

    /// Encodes EAPOL-Logoff with an optional explicit Ruijie trailer.
    ///
    /// # Errors
    ///
    /// Returns an error if the final Ethernet payload exceeds 1,500 bytes or
    /// the configured Ethernet envelope is invalid.
    pub fn encode_logoff(&self, ruijie_trailer: &[u8]) -> Result<Vec<u8>> {
        self.encode(EapolPacketType::Logoff, &[], ruijie_trailer)
    }

    /// Encodes an EAP packet and optional Ruijie VSA trailer.
    ///
    /// `eap_packet` must already be validated and encoded by
    /// `rjconnect-eapol`; this boundary deliberately does not reinterpret
    /// authentication semantics.
    ///
    /// # Errors
    ///
    /// Returns an error if the final Ethernet payload exceeds 1,500 bytes or
    /// the configured Ethernet envelope is invalid.
    pub fn encode_eap(&self, eap_packet: &[u8], ruijie_trailer: &[u8]) -> Result<Vec<u8>> {
        EapPacket::parse(eap_packet)?;
        self.encode(EapolPacketType::EapPacket, eap_packet, ruijie_trailer)
    }

    fn encode(
        &self,
        packet_type: EapolPacketType,
        payload: &[u8],
        trailer: &[u8],
    ) -> Result<Vec<u8>> {
        if !trailer.is_empty() {
            WiredVendorTrailer::parse(trailer)?;
        }
        let eapol = EapolPacket {
            version: self.eapol_version,
            packet_type,
            payload,
            trailing: trailer,
        }
        .encode_with_trailing()?;
        if eapol.len() > MAX_ETHERNET_PAYLOAD_LENGTH {
            return Err(WiredFrameError::PayloadTooLarge {
                actual: eapol.len(),
                maximum: MAX_ETHERNET_PAYLOAD_LENGTH,
            });
        }

        EthernetFrame {
            destination: self.destination,
            source: self.source,
            vlan_tags: self.vlan_tags.clone(),
            ether_type: ETHERTYPE_EAPOL,
            payload: &eapol,
        }
        .encode()
        .map_err(Into::into)
    }
}

/// Error returned by the complete wired frame boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WiredFrameError {
    /// A nested Ethernet/EAPOL/EAP codec rejected the input.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Ethernet frame did not carry EAPOL.
    #[error("expected EAPOL EtherType 0x888e, got 0x{actual:04x}")]
    UnexpectedEtherType {
        /// Actual `EtherType`.
        actual: u16,
    },
    /// EAPOL Start or Logoff declared an unexpected payload.
    #[error("EAPOL {packet_type:?} must not declare a payload, got {length} bytes")]
    UnexpectedControlPayload {
        /// Invalid packet type.
        packet_type: EapolPacketType,
        /// Declared payload byte count.
        length: usize,
    },
    /// Complete EAPOL data and trailer exceed a normal Ethernet payload.
    #[error("Ethernet payload is too large: {actual} bytes, maximum {maximum}")]
    PayloadTooLarge {
        /// Actual EAPOL plus trailer length.
        actual: usize,
        /// Maximum accepted Ethernet payload.
        maximum: usize,
    },
    /// Wired Ruijie trailer failed structural validation.
    #[error(transparent)]
    RuijieTrailer(#[from] WiredVendorTrailerError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rjconnect_eapol::{EapMethod, EapPacket};
    use rjconnect_ruijie::{
        AttributeKind, RUIJIE_VENDOR_ID, RadiusAttributeWriter, WIRED_PREAMBLE_LENGTH,
    };

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn Error>>;

    fn encoder() -> WiredFrameEncoder {
        WiredFrameEncoder::new(
            MacAddress::new([2, 0, 0, 0, 0, 1]),
            MacAddress::RUIJIE_GROUP,
        )
    }

    fn trailer_with_attributes(attributes: &[u8]) -> Vec<u8> {
        let mut trailer = vec![0; WIRED_PREAMBLE_LENGTH];
        trailer[23..27].copy_from_slice(&RUIJIE_VENDOR_ID.to_be_bytes());
        trailer[64..68].copy_from_slice(&RUIJIE_VENDOR_ID.to_be_bytes());
        trailer.extend_from_slice(attributes);
        trailer
    }

    #[test]
    fn start_round_trips_without_declared_or_trailing_payload() -> TestResult {
        let wire = encoder().encode_start()?;
        let frame = InboundWiredFrame::parse(&wire)?;

        assert_eq!(frame.eapol.packet_type, EapolPacketType::Start);
        assert!(frame.eapol.payload.is_empty());
        assert!(frame.eapol.trailing.is_empty());
        assert!(frame.eap.is_none());
        Ok(())
    }

    #[test]
    fn identity_and_radius_trailer_keep_independent_lengths() -> TestResult {
        let eap = EapPacket::response(9, EapMethod::Identity, b"student").encode()?;
        let mut attributes = RadiusAttributeWriter::new();
        attributes.push(AttributeKind::OS_BITS, &[64])?;
        let trailer = trailer_with_attributes(&attributes.finish());
        let wire = encoder().encode_eap(&eap, &trailer)?;
        let frame = InboundWiredFrame::parse(&wire)?;

        assert_eq!(frame.eapol.payload, eap);
        assert_eq!(frame.eapol.trailing, trailer);
        assert_eq!(
            frame.eap.as_ref().map(|packet| packet.payload),
            Some(&b"student"[..])
        );
        let trailer = frame.ruijie_trailer()?;
        let mut attributes = trailer.attributes()?;
        let Some(attribute) = attributes.next() else {
            return Err("missing Ruijie attribute".into());
        };
        let attribute = attribute?;
        assert_eq!(attribute.kind, AttributeKind::OS_BITS);
        assert_eq!(attribute.value, [64]);
        assert_eq!(attributes.next(), None);
        Ok(())
    }

    #[test]
    fn rejects_non_eapol_frame() -> TestResult {
        let payload = [0; 20];
        let wire = EthernetFrame {
            destination: MacAddress::PAE_GROUP,
            source: MacAddress::new([2, 0, 0, 0, 0, 1]),
            vlan_tags: Vec::new(),
            ether_type: 0x0800,
            payload: &payload,
        }
        .encode()?;

        assert_eq!(
            InboundWiredFrame::parse(&wire),
            Err(WiredFrameError::UnexpectedEtherType { actual: 0x0800 })
        );
        Ok(())
    }

    #[test]
    fn rejects_eapol_payload_above_ethernet_mtu() -> TestResult {
        let trailer = trailer_with_attributes(&[]);
        let method_payload = vec![0; MAX_ETHERNET_PAYLOAD_LENGTH - 78];
        let eap = EapPacket::response(1, EapMethod::Identity, &method_payload).encode()?;

        assert_eq!(
            eap.len() + 4 + trailer.len(),
            MAX_ETHERNET_PAYLOAD_LENGTH + 1
        );
        assert_eq!(
            encoder().encode_eap(&eap, &trailer),
            Err(WiredFrameError::PayloadTooLarge {
                actual: MAX_ETHERNET_PAYLOAD_LENGTH + 1,
                maximum: MAX_ETHERNET_PAYLOAD_LENGTH,
            })
        );
        Ok(())
    }
}
