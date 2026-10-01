//! Ruijie RADIUS Vendor-Specific Attributes contained in a wired vendor
//! trailer after its fixed preamble.
//!
//! ```text
//!  0        1        2                 6        7        8
//!  +--------+--------+-----------------+--------+--------+-------------
//!  | 0x1a   | outer  | vendor 0x1311   | kind   | inner  | value
//!  +--------+--------+-----------------+--------+--------+-------------
//! ```
//!
//! `outer` counts the complete attribute beginning at byte zero. `inner`
//! counts the kind and inner-length bytes plus the value. Consequently
//! `outer == inner + 6`, and the outer one-byte length limits a value to 247
//! bytes even though the inner field alone could represent 253 bytes.

use thiserror::Error;

use crate::{AttributeKind, MAX_VENDOR_PAYLOAD_LENGTH};

/// RADIUS attribute type assigned to Vendor-Specific Attributes.
pub const RADIUS_VENDOR_SPECIFIC_TYPE: u8 = 0x1a;
/// Ruijie enterprise identifier found in the recovered wired protocol.
pub const RUIJIE_VENDOR_ID: u32 = 0x0000_1311;

const HEADER_LENGTH: usize = 8;
// The outer RADIUS length counts this eight-byte header and is one octet.
const MAX_VALUE_LENGTH: usize = 247;

/// Result type returned by wired vendor-attribute codecs.
pub type Result<T> = std::result::Result<T, RadiusAttributeError>;

/// A borrowed Ruijie RADIUS Vendor-Specific Attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadiusAttribute<'a> {
    /// Ruijie inner attribute type.
    pub kind: AttributeKind,
    /// Inner attribute value bytes.
    pub value: &'a [u8],
}

/// Structural error in a wired vendor-attribute block.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RadiusAttributeError {
    /// Complete vendor block exceeds the product boundary.
    #[error("wired vendor payload exceeds {maximum} bytes: {actual}")]
    PayloadTooLarge {
        /// Maximum accepted byte count.
        maximum: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// Fewer than eight bytes remain for a complete header.
    #[error("truncated wired vendor attribute at offset {offset}: {remaining} bytes remain")]
    TruncatedHeader {
        /// Byte offset of the incomplete attribute.
        offset: usize,
        /// Bytes remaining at the offset.
        remaining: usize,
    },
    /// Outer RADIUS attribute type is not Vendor-Specific.
    #[error("unexpected RADIUS attribute type 0x{actual:02x} at offset {offset}")]
    UnexpectedOuterType {
        /// Byte offset of the attribute.
        offset: usize,
        /// Unexpected type byte.
        actual: u8,
    },
    /// Vendor enterprise identifier is not Ruijie.
    #[error("unexpected vendor id 0x{actual:08x} at offset {offset}")]
    UnexpectedVendorId {
        /// Byte offset of the attribute.
        offset: usize,
        /// Unexpected enterprise identifier.
        actual: u32,
    },
    /// Outer length is shorter than the fixed eight-byte header.
    #[error("wired vendor attribute at offset {offset} has invalid outer length {length}")]
    InvalidOuterLength {
        /// Byte offset of the attribute.
        offset: usize,
        /// Invalid outer length.
        length: usize,
    },
    /// Inner length is shorter than its type and length bytes.
    #[error("wired vendor attribute at offset {offset} has invalid inner length {length}")]
    InvalidInnerLength {
        /// Byte offset of the attribute.
        offset: usize,
        /// Invalid inner length.
        length: usize,
    },
    /// Outer and inner lengths disagree.
    #[error(
        "wired vendor attribute at offset {offset} has outer length {outer} and inner length {inner}"
    )]
    InconsistentLengths {
        /// Byte offset of the attribute.
        offset: usize,
        /// Outer byte count.
        outer: usize,
        /// Inner byte count.
        inner: usize,
    },
    /// Declared outer length exceeds remaining bytes.
    #[error(
        "wired vendor attribute at offset {offset} declares {declared} bytes, {remaining} remain"
    )]
    TruncatedValue {
        /// Byte offset of the attribute.
        offset: usize,
        /// Declared outer byte count.
        declared: usize,
        /// Remaining byte count.
        remaining: usize,
    },
    /// Value cannot fit both one-byte length fields.
    #[error("wired vendor attribute 0x{kind:02x} value is too large: {length} bytes")]
    ValueTooLarge {
        /// Raw inner kind.
        kind: u8,
        /// Value byte count.
        length: usize,
    },
}

/// Iterator over a validated wired vendor-attribute block.
#[derive(Debug, Clone)]
pub struct RadiusAttributeReader<'a> {
    input: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> RadiusAttributeReader<'a> {
    /// Creates a reader after validating the complete block boundary.
    ///
    /// # Errors
    ///
    /// Returns [`RadiusAttributeError::PayloadTooLarge`] when `input` exceeds
    /// [`MAX_VENDOR_PAYLOAD_LENGTH`].
    pub const fn new(input: &'a [u8]) -> Result<Self> {
        if input.len() > MAX_VENDOR_PAYLOAD_LENGTH {
            return Err(RadiusAttributeError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: input.len(),
            });
        }
        Ok(Self {
            input,
            offset: 0,
            failed: false,
        })
    }

    const fn fail(&mut self, error: RadiusAttributeError) -> Result<RadiusAttribute<'a>> {
        self.failed = true;
        Err(error)
    }
}

impl<'a> Iterator for RadiusAttributeReader<'a> {
    type Item = Result<RadiusAttribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.input.len() {
            return None;
        }

        let start = self.offset;
        let remaining = self.input.len() - start;
        if remaining < HEADER_LENGTH {
            return Some(self.fail(RadiusAttributeError::TruncatedHeader {
                offset: start,
                remaining,
            }));
        }
        if self.input[start] != RADIUS_VENDOR_SPECIFIC_TYPE {
            return Some(self.fail(RadiusAttributeError::UnexpectedOuterType {
                offset: start,
                actual: self.input[start],
            }));
        }

        let outer_length = usize::from(self.input[start + 1]);
        if outer_length < HEADER_LENGTH {
            return Some(self.fail(RadiusAttributeError::InvalidOuterLength {
                offset: start,
                length: outer_length,
            }));
        }
        if remaining < outer_length {
            return Some(self.fail(RadiusAttributeError::TruncatedValue {
                offset: start,
                declared: outer_length,
                remaining,
            }));
        }

        let vendor_id = u32::from_be_bytes([
            self.input[start + 2],
            self.input[start + 3],
            self.input[start + 4],
            self.input[start + 5],
        ]);
        if vendor_id != RUIJIE_VENDOR_ID {
            return Some(self.fail(RadiusAttributeError::UnexpectedVendorId {
                offset: start,
                actual: vendor_id,
            }));
        }

        let inner_length = usize::from(self.input[start + 7]);
        if inner_length < 2 {
            return Some(self.fail(RadiusAttributeError::InvalidInnerLength {
                offset: start,
                length: inner_length,
            }));
        }
        if outer_length != inner_length + 6 {
            return Some(self.fail(RadiusAttributeError::InconsistentLengths {
                offset: start,
                outer: outer_length,
                inner: inner_length,
            }));
        }

        self.offset += outer_length;
        Some(Ok(RadiusAttribute {
            kind: AttributeKind::new(self.input[start + 6]),
            value: &self.input[start + HEADER_LENGTH..self.offset],
        }))
    }
}

/// Encoder for wired Ruijie RADIUS Vendor-Specific Attributes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RadiusAttributeWriter {
    output: Vec<u8>,
}

impl RadiusAttributeWriter {
    /// Creates an empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { output: Vec::new() }
    }

    /// Appends one complete RADIUS Vendor-Specific Attribute.
    ///
    /// # Errors
    ///
    /// Returns an error when the value exceeds 247 bytes or the accumulated
    /// block would exceed [`MAX_VENDOR_PAYLOAD_LENGTH`].
    pub fn push(&mut self, kind: AttributeKind, value: &[u8]) -> Result<()> {
        if value.len() > MAX_VALUE_LENGTH {
            return Err(RadiusAttributeError::ValueTooLarge {
                kind: kind.raw(),
                length: value.len(),
            });
        }
        let outer_length = value.len() + HEADER_LENGTH;
        let next_length = self.output.len() + outer_length;
        if next_length > MAX_VENDOR_PAYLOAD_LENGTH {
            return Err(RadiusAttributeError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: next_length,
            });
        }
        let outer_wire =
            u8::try_from(outer_length).map_err(|_error| RadiusAttributeError::ValueTooLarge {
                kind: kind.raw(),
                length: value.len(),
            })?;
        let inner_wire = u8::try_from(value.len() + 2).map_err(|_error| {
            RadiusAttributeError::ValueTooLarge {
                kind: kind.raw(),
                length: value.len(),
            }
        })?;

        self.output.push(RADIUS_VENDOR_SPECIFIC_TYPE);
        self.output.push(outer_wire);
        self.output
            .extend_from_slice(&RUIJIE_VENDOR_ID.to_be_bytes());
        self.output.push(kind.raw());
        self.output.push(inner_wire);
        self.output.extend_from_slice(value);
        Ok(())
    }

    /// Returns the encoded wired vendor block.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.output
    }

    /// Returns the current encoded byte count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.output.len()
    }

    /// Returns whether no attributes have been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.output.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_recovered_single_byte_attribute_layout() -> Result<()> {
        let mut writer = RadiusAttributeWriter::new();
        writer.push(AttributeKind::new(0x35), &[3])?;
        let bytes = writer.finish();

        assert_eq!(
            bytes,
            [0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x35, 0x03, 0x03]
        );
        assert_eq!(
            RadiusAttributeReader::new(&bytes)?.collect::<Result<Vec<_>>>()?,
            [RadiusAttribute {
                kind: AttributeKind::new(0x35),
                value: &[3],
            }]
        );
        Ok(())
    }

    #[test]
    fn round_trips_multiple_and_unknown_attributes() -> Result<()> {
        let mut writer = RadiusAttributeWriter::new();
        writer.push(AttributeKind::REAUTH_INTERVAL, &60_u32.to_be_bytes())?;
        writer.push(AttributeKind::new(0xfe), b"future")?;
        let bytes = writer.finish();
        let values = RadiusAttributeReader::new(&bytes)?.collect::<Result<Vec<_>>>()?;

        assert_eq!(values[0].kind, AttributeKind::REAUTH_INTERVAL);
        assert_eq!(values[0].value, 60_u32.to_be_bytes());
        assert_eq!(values[1].kind, AttributeKind::new(0xfe));
        assert_eq!(values[1].value, b"future");
        Ok(())
    }

    #[test]
    fn rejects_wrong_outer_type_and_vendor() -> Result<()> {
        let mut wrong_type = [0x1b, 8, 0, 0, 0x13, 0x11, 1, 2];
        let mut reader = RadiusAttributeReader::new(&wrong_type)?;
        assert_eq!(
            reader.next(),
            Some(Err(RadiusAttributeError::UnexpectedOuterType {
                offset: 0,
                actual: 0x1b,
            }))
        );

        wrong_type[0] = RADIUS_VENDOR_SPECIFIC_TYPE;
        wrong_type[5] = 0x12;
        let mut reader = RadiusAttributeReader::new(&wrong_type)?;
        assert_eq!(
            reader.next(),
            Some(Err(RadiusAttributeError::UnexpectedVendorId {
                offset: 0,
                actual: 0x0000_1312,
            }))
        );
        Ok(())
    }

    #[test]
    fn rejects_inconsistent_and_truncated_lengths() -> Result<()> {
        let inconsistent = [0x1a, 9, 0, 0, 0x13, 0x11, 1, 2, 0];
        let mut reader = RadiusAttributeReader::new(&inconsistent)?;
        assert_eq!(
            reader.next(),
            Some(Err(RadiusAttributeError::InconsistentLengths {
                offset: 0,
                outer: 9,
                inner: 2,
            }))
        );

        let truncated = [0x1a, 10, 0, 0, 0x13, 0x11, 1, 4, 0];
        let mut reader = RadiusAttributeReader::new(&truncated)?;
        assert_eq!(
            reader.next(),
            Some(Err(RadiusAttributeError::TruncatedValue {
                offset: 0,
                declared: 10,
                remaining: 9,
            }))
        );
        Ok(())
    }

    #[test]
    fn enforces_outer_length_value_limit() -> Result<()> {
        let mut writer = RadiusAttributeWriter::new();
        writer.push(AttributeKind::new(1), &[0; MAX_VALUE_LENGTH])?;
        assert_eq!(writer.len(), usize::from(u8::MAX));
        assert_eq!(
            writer.push(AttributeKind::new(2), &[0; MAX_VALUE_LENGTH + 1]),
            Err(RadiusAttributeError::ValueTooLarge {
                kind: 2,
                length: MAX_VALUE_LENGTH + 1,
            })
        );
        Ok(())
    }

    #[test]
    fn preserves_zero_length_value() -> Result<()> {
        let mut writer = RadiusAttributeWriter::new();
        writer.push(AttributeKind::new(0x42), &[])?;
        let bytes = writer.finish();
        let values = RadiusAttributeReader::new(&bytes)?.collect::<Result<Vec<_>>>()?;

        assert_eq!(bytes, [0x1a, 8, 0, 0, 0x13, 0x11, 0x42, 2]);
        assert_eq!(values[0].kind, AttributeKind::new(0x42));
        assert!(values[0].value.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_short_outer_and_inner_lengths() -> Result<()> {
        let mut outer = [0x1a, 7, 0, 0, 0x13, 0x11, 1, 2];
        let mut reader = RadiusAttributeReader::new(&outer)?;
        assert_eq!(
            reader.next(),
            Some(Err(RadiusAttributeError::InvalidOuterLength {
                offset: 0,
                length: 7,
            }))
        );

        outer[1] = 8;
        outer[7] = 1;
        let mut reader = RadiusAttributeReader::new(&outer)?;
        assert_eq!(
            reader.next(),
            Some(Err(RadiusAttributeError::InvalidInnerLength {
                offset: 0,
                length: 1,
            }))
        );
        Ok(())
    }

    #[test]
    fn rejects_truncated_header_and_oversized_block() -> Result<()> {
        let mut reader = RadiusAttributeReader::new(&[0x1a, 8, 0])?;
        assert_eq!(
            reader.next(),
            Some(Err(RadiusAttributeError::TruncatedHeader {
                offset: 0,
                remaining: 3,
            }))
        );
        assert_eq!(reader.next(), None);

        let payload = vec![0; MAX_VENDOR_PAYLOAD_LENGTH + 1];
        assert!(matches!(
            RadiusAttributeReader::new(&payload),
            Err(RadiusAttributeError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual,
            }) if actual == MAX_VENDOR_PAYLOAD_LENGTH + 1
        ));
        Ok(())
    }

    #[test]
    fn writer_enforces_cumulative_block_limit() -> Result<()> {
        let value = [0; MAX_VALUE_LENGTH];
        let mut writer = RadiusAttributeWriter::new();
        for kind in 0..5 {
            writer.push(AttributeKind::new(kind), &value)?;
        }

        assert_eq!(writer.len(), 5 * usize::from(u8::MAX));
        assert_eq!(
            writer.push(AttributeKind::new(5), &value),
            Err(RadiusAttributeError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: 6 * usize::from(u8::MAX),
            })
        );
        Ok(())
    }
}
