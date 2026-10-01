//! RFC 3748 EAP packet codec.
//!
//! ```text
//!  0        1        2                 4        5
//!  +--------+--------+-----------------+--------+-------------
//!  | code   | id     | packet length   | method | method data
//!  +--------+--------+-----------------+--------+-------------
//! ```
//!
//! The method byte exists only on Request and Response packets. Success and
//! Failure must have a declared length of exactly four bytes. Unknown codes
//! and methods retain their raw numeric value for diagnostics and future
//! protocol extensions.

use crate::error::{CodecError, Result};

const HEADER_LENGTH: usize = 4;

/// EAP packet code defined by RFC 3748.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapCode {
    /// Method request sent by the authenticator.
    Request,
    /// Method response sent by the peer.
    Response,
    /// Authentication succeeded.
    Success,
    /// Authentication failed.
    Failure,
    /// Value not known by this version of the codec.
    Unknown(u8),
}

impl From<u8> for EapCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Response,
            3 => Self::Success,
            4 => Self::Failure,
            other => Self::Unknown(other),
        }
    }
}

impl From<EapCode> for u8 {
    fn from(value: EapCode) -> Self {
        match value {
            EapCode::Request => 1,
            EapCode::Response => 2,
            EapCode::Success => 3,
            EapCode::Failure => 4,
            EapCode::Unknown(raw) => raw,
        }
    }
}

/// EAP method type, including the legacy Ruijie private method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapMethod {
    /// Identity exchange.
    Identity,
    /// Human-readable notification.
    Notification,
    /// Legacy NAK response.
    Nak,
    /// MD5 challenge.
    Md5Challenge,
    /// One-time password.
    Otp,
    /// Generic token card.
    Gtc,
    /// Legacy Ruijie private method (type 7).
    RuijiePrivate,
    /// EAP-TLS.
    Tls,
    /// PEAP.
    Peap,
    /// Expanded vendor method.
    Expanded,
    /// Method not known by this version of the codec.
    Unknown(u8),
}

impl From<u8> for EapMethod {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Identity,
            2 => Self::Notification,
            3 => Self::Nak,
            4 => Self::Md5Challenge,
            5 => Self::Otp,
            6 => Self::Gtc,
            7 => Self::RuijiePrivate,
            13 => Self::Tls,
            25 => Self::Peap,
            254 => Self::Expanded,
            other => Self::Unknown(other),
        }
    }
}

impl From<EapMethod> for u8 {
    fn from(value: EapMethod) -> Self {
        match value {
            EapMethod::Identity => 1,
            EapMethod::Notification => 2,
            EapMethod::Nak => 3,
            EapMethod::Md5Challenge => 4,
            EapMethod::Otp => 5,
            EapMethod::Gtc => 6,
            EapMethod::RuijiePrivate => 7,
            EapMethod::Tls => 13,
            EapMethod::Peap => 25,
            EapMethod::Expanded => 254,
            EapMethod::Unknown(raw) => raw,
        }
    }
}

/// A borrowed EAP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket<'a> {
    /// EAP packet code.
    pub code: EapCode,
    /// Request/response identifier.
    pub identifier: u8,
    /// Method for request/response packets.
    pub method: Option<EapMethod>,
    /// Method data or unknown-code payload.
    pub payload: &'a [u8],
    /// Bytes following the declared EAP packet.
    pub trailing: &'a [u8],
}

impl<'a> EapPacket<'a> {
    /// Parses an EAP packet.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated data, inconsistent declared lengths,
    /// request/response packets without a method, or terminal packets whose
    /// declared length is not exactly four bytes.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        if input.len() < HEADER_LENGTH {
            return Err(CodecError::Truncated {
                layer: "EAP",
                needed: HEADER_LENGTH,
                actual: input.len(),
            });
        }

        let declared_length = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if declared_length < HEADER_LENGTH {
            return Err(CodecError::InvalidLength {
                layer: "EAP",
                declared: declared_length,
                available: input.len(),
            });
        }
        if input.len() < declared_length {
            return Err(CodecError::InvalidLength {
                layer: "EAP",
                declared: declared_length,
                available: input.len(),
            });
        }

        let code = EapCode::from(input[0]);
        let (method, payload_start) = match code {
            EapCode::Request | EapCode::Response => {
                if declared_length < HEADER_LENGTH + 1 {
                    return Err(CodecError::MissingEapMethod);
                }
                (Some(EapMethod::from(input[4])), 5)
            }
            EapCode::Success | EapCode::Failure => {
                if declared_length != HEADER_LENGTH {
                    return Err(CodecError::InvalidTerminalEapLength {
                        length: declared_length,
                    });
                }
                (None, HEADER_LENGTH)
            }
            EapCode::Unknown(_) => (None, HEADER_LENGTH),
        };

        Ok(Self {
            code,
            identifier: input[1],
            method,
            payload: &input[payload_start..declared_length],
            trailing: &input[declared_length..],
        })
    }

    /// Constructs a method response packet.
    #[must_use]
    pub const fn response(identifier: u8, method: EapMethod, payload: &'a [u8]) -> Self {
        Self {
            code: EapCode::Response,
            identifier,
            method: Some(method),
            payload,
            trailing: &[],
        }
    }

    /// Encodes the declared EAP packet without trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet invariant is invalid or the encoded
    /// length does not fit the EAP 16-bit length field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let method_length = match self.code {
            EapCode::Request | EapCode::Response => {
                if self.method.is_none() {
                    return Err(CodecError::MissingEapMethod);
                }
                1
            }
            EapCode::Success | EapCode::Failure => {
                if !self.payload.is_empty() || self.method.is_some() {
                    return Err(CodecError::InvalidTerminalEapLength {
                        length: HEADER_LENGTH
                            + usize::from(self.method.is_some())
                            + self.payload.len(),
                    });
                }
                0
            }
            EapCode::Unknown(_) => 0,
        };
        let length = HEADER_LENGTH + method_length + self.payload.len();
        let encoded_length =
            u16::try_from(length).map_err(|_error| CodecError::PayloadTooLarge {
                layer: "EAP",
                length: self.payload.len(),
            })?;

        let mut output = Vec::with_capacity(length);
        output.push(self.code.into());
        output.push(self.identifier);
        output.extend_from_slice(&encoded_length.to_be_bytes());
        if let Some(method) = self.method {
            output.push(method.into());
        }
        output.extend_from_slice(self.payload);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_request_and_preserves_padding() -> Result<()> {
        let packet = EapPacket::parse(&[1, 9, 0, 5, 1, 0, 0])?;

        assert_eq!(packet.code, EapCode::Request);
        assert_eq!(packet.identifier, 9);
        assert_eq!(packet.method, Some(EapMethod::Identity));
        assert!(packet.payload.is_empty());
        assert_eq!(packet.trailing, [0, 0]);
        Ok(())
    }

    #[test]
    fn round_trips_method_response() -> Result<()> {
        let packet = EapPacket::response(3, EapMethod::Identity, b"student");
        let encoded = packet.encode()?;
        let decoded = EapPacket::parse(&encoded)?;

        assert_eq!(decoded, packet);
        Ok(())
    }

    #[test]
    fn rejects_request_without_method() {
        assert_eq!(
            EapPacket::parse(&[1, 9, 0, 4]),
            Err(CodecError::MissingEapMethod)
        );
    }

    #[test]
    fn rejects_success_with_payload() {
        assert_eq!(
            EapPacket::parse(&[3, 9, 0, 5, 0]),
            Err(CodecError::InvalidTerminalEapLength { length: 5 })
        );
    }

    #[test]
    fn round_trips_unknown_method() -> Result<()> {
        let packet = EapPacket::response(11, EapMethod::Unknown(199), b"extension");
        let encoded = packet.encode()?;

        assert_eq!(EapPacket::parse(&encoded)?, packet);
        Ok(())
    }

    #[test]
    fn rejects_declared_length_smaller_than_header() {
        assert_eq!(
            EapPacket::parse(&[1, 1, 0, 3]),
            Err(CodecError::InvalidLength {
                layer: "EAP",
                declared: 3,
                available: 4,
            })
        );
    }

    #[test]
    fn rejects_declared_length_beyond_input() {
        assert_eq!(
            EapPacket::parse(&[1, 1, 0, 6, 1]),
            Err(CodecError::InvalidLength {
                layer: "EAP",
                declared: 6,
                available: 5,
            })
        );
    }

    #[test]
    fn accepts_largest_encodable_method_payload() -> Result<()> {
        let payload = vec![0x7b; usize::from(u16::MAX) - 5];
        let packet = EapPacket::response(1, EapMethod::Expanded, &payload);
        let encoded = packet.encode()?;
        let decoded = EapPacket::parse(&encoded)?;

        assert_eq!(encoded.len(), usize::from(u16::MAX));
        assert_eq!(decoded.payload.len(), payload.len());
        Ok(())
    }

    #[test]
    fn rejects_method_payload_larger_than_wire_packet() {
        let payload = vec![0; usize::from(u16::MAX) - 4];
        let packet = EapPacket::response(1, EapMethod::Expanded, &payload);

        assert_eq!(
            packet.encode(),
            Err(CodecError::PayloadTooLarge {
                layer: "EAP",
                length: payload.len(),
            })
        );
    }
}
