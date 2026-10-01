//! IEEE 802.1X EAPOL header codec.
//!
//! ```text
//!  0        1        2                 4
//!  +--------+--------+-----------------+-----------------
//!  |version | type   | payload length  | payload
//!  +--------+--------+-----------------+-----------------
//! ```
//!
//! Ethernet padding is not covered by the EAPOL length field. Parsing returns
//! it separately so callers never feed padding into the EAP decoder.

use crate::error::{CodecError, Result};

const HEADER_LENGTH: usize = 4;

/// IEEE 802.1X packet type carried by an EAPOL header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapolPacketType {
    /// EAP packet.
    EapPacket,
    /// Start authentication.
    Start,
    /// End authentication.
    Logoff,
    /// EAPOL-Key packet.
    Key,
    /// Encapsulated ASF alert.
    EncapsulatedAsfAlert,
    /// Value not known by this version of the codec.
    Unknown(u8),
}

impl From<u8> for EapolPacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::EapPacket,
            1 => Self::Start,
            2 => Self::Logoff,
            3 => Self::Key,
            4 => Self::EncapsulatedAsfAlert,
            other => Self::Unknown(other),
        }
    }
}

impl From<EapolPacketType> for u8 {
    fn from(value: EapolPacketType) -> Self {
        match value {
            EapolPacketType::EapPacket => 0,
            EapolPacketType::Start => 1,
            EapolPacketType::Logoff => 2,
            EapolPacketType::Key => 3,
            EapolPacketType::EncapsulatedAsfAlert => 4,
            EapolPacketType::Unknown(raw) => raw,
        }
    }
}

/// A borrowed EAPOL packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolPacket<'a> {
    /// IEEE 802.1X protocol version.
    pub version: u8,
    /// EAPOL packet type.
    pub packet_type: EapolPacketType,
    /// Declared EAPOL payload.
    pub payload: &'a [u8],
    /// Bytes following the declared payload, normally Ethernet padding.
    pub trailing: &'a [u8],
}

impl<'a> EapolPacket<'a> {
    /// Parses an EAPOL packet and separates any trailing Ethernet padding.
    ///
    /// # Errors
    ///
    /// Returns an error for a truncated header or a declared payload longer
    /// than the containing byte slice.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        if input.len() < HEADER_LENGTH {
            return Err(CodecError::Truncated {
                layer: "EAPOL",
                needed: HEADER_LENGTH,
                actual: input.len(),
            });
        }

        let payload_length = usize::from(u16::from_be_bytes([input[2], input[3]]));
        let packet_length = HEADER_LENGTH + payload_length;
        if input.len() < packet_length {
            return Err(CodecError::InvalidLength {
                layer: "EAPOL",
                declared: packet_length,
                available: input.len(),
            });
        }

        Ok(Self {
            version: input[0],
            packet_type: input[1].into(),
            payload: &input[HEADER_LENGTH..packet_length],
            trailing: &input[packet_length..],
        })
    }

    /// Encodes an EAPOL packet without trailing padding.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::PayloadTooLarge`] when the payload does not fit
    /// the EAPOL 16-bit length field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload_length =
            u16::try_from(self.payload.len()).map_err(|_error| CodecError::PayloadTooLarge {
                layer: "EAPOL",
                length: self.payload.len(),
            })?;
        let mut output = Vec::with_capacity(HEADER_LENGTH + self.payload.len());
        output.push(self.version);
        output.push(self.packet_type.into());
        output.extend_from_slice(&payload_length.to_be_bytes());
        output.extend_from_slice(self.payload);
        Ok(output)
    }

    /// Encodes the declared packet and then appends explicit trailing bytes.
    ///
    /// Legacy wired Ruijie frames place RADIUS Vendor-Specific Attributes
    /// after the declared EAPOL payload. This method makes that non-standard
    /// extension explicit; ordinary callers should prefer [`Self::encode`].
    /// Ethernet padding, when needed, also belongs in `trailing` and is never
    /// included in the EAPOL length field.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::PayloadTooLarge`] under the same condition as
    /// [`Self::encode`]. Trailing bytes are bounded by the containing Ethernet
    /// frame rather than the EAPOL 16-bit payload length.
    pub fn encode_with_trailing(&self) -> Result<Vec<u8>> {
        let mut output = self.encode()?;
        output.extend_from_slice(self.trailing);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_declared_payload_from_padding() -> Result<()> {
        let packet = EapolPacket::parse(&[1, 0, 0, 4, 1, 7, 0, 4, 0, 0])?;

        assert_eq!(packet.version, 1);
        assert_eq!(packet.packet_type, EapolPacketType::EapPacket);
        assert_eq!(packet.payload, [1, 7, 0, 4]);
        assert_eq!(packet.trailing, [0, 0]);
        assert_eq!(packet.encode()?, [1, 0, 0, 4, 1, 7, 0, 4]);
        assert_eq!(
            packet.encode_with_trailing()?,
            [1, 0, 0, 4, 1, 7, 0, 4, 0, 0]
        );
        Ok(())
    }

    #[test]
    fn rejects_declared_length_beyond_input() {
        assert_eq!(
            EapolPacket::parse(&[1, 0, 0, 5, 1, 2, 3, 4]),
            Err(CodecError::InvalidLength {
                layer: "EAPOL",
                declared: 9,
                available: 8,
            })
        );
    }

    #[test]
    fn round_trips_unknown_type() -> Result<()> {
        let packet = EapolPacket {
            version: 2,
            packet_type: EapolPacketType::Unknown(0xc0),
            payload: b"vendor",
            trailing: &[],
        };
        let encoded = packet.encode()?;

        assert_eq!(EapolPacket::parse(&encoded)?, packet);
        Ok(())
    }

    #[test]
    fn accepts_maximum_payload_length() -> Result<()> {
        let payload = vec![0x5a; usize::from(u16::MAX)];
        let packet = EapolPacket {
            version: 1,
            packet_type: EapolPacketType::Key,
            payload: &payload,
            trailing: &[],
        };
        let encoded = packet.encode()?;
        let decoded = EapolPacket::parse(&encoded)?;

        assert_eq!(decoded.payload.len(), usize::from(u16::MAX));
        assert_eq!(decoded.payload.first(), Some(&0x5a));
        assert_eq!(decoded.payload.last(), Some(&0x5a));
        Ok(())
    }

    #[test]
    fn rejects_payload_larger_than_wire_length() {
        let payload = vec![0; usize::from(u16::MAX) + 1];
        let packet = EapolPacket {
            version: 1,
            packet_type: EapolPacketType::EapPacket,
            payload: &payload,
            trailing: &[],
        };

        assert_eq!(
            packet.encode(),
            Err(CodecError::PayloadTooLarge {
                layer: "EAPOL",
                length: usize::from(u16::MAX) + 1,
            })
        );
    }
}
