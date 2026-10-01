//! Compact attributes used inside the recovered PEAP vendor block.
//!
//! ```text
//!  0        1        2
//!  +--------+--------+-----------------
//!  | kind   | length | value
//!  +--------+--------+-----------------
//! ```
//!
//! `length` counts value bytes only. An individual value is therefore limited
//! to 255 bytes.

use thiserror::Error;

use crate::{AttributeKind, MAX_VENDOR_PAYLOAD_LENGTH};

/// Result type returned by compact attribute codecs.
pub type Result<T> = std::result::Result<T, CompactAttributeError>;

/// A borrowed compact private attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactAttribute<'a> {
    /// Attribute type byte.
    pub kind: AttributeKind,
    /// Attribute value bytes.
    pub value: &'a [u8],
}

/// Structural error in a compact private-attribute stream.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CompactAttributeError {
    /// The overall vendor block exceeds the accepted protocol boundary.
    #[error("compact vendor payload exceeds {maximum} bytes: {actual}")]
    PayloadTooLarge {
        /// Maximum accepted byte count.
        maximum: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// A header ended after only one byte.
    #[error("truncated compact attribute header at offset {offset}: {remaining} byte remains")]
    TruncatedHeader {
        /// Byte offset of the incomplete header.
        offset: usize,
        /// Bytes remaining at the offset.
        remaining: usize,
    },
    /// An attribute declared more bytes than remain in the vendor block.
    #[error(
        "compact attribute 0x{kind:02x} at offset {offset} declares {declared} bytes, {remaining} remain"
    )]
    TruncatedValue {
        /// Byte offset of the attribute header.
        offset: usize,
        /// Raw attribute kind.
        kind: u8,
        /// Declared value length.
        declared: usize,
        /// Available value bytes.
        remaining: usize,
    },
    /// A value cannot fit the one-byte length field.
    #[error("compact attribute 0x{kind:02x} value is too large: {length} bytes")]
    ValueTooLarge {
        /// Raw attribute kind.
        kind: u8,
        /// Value byte count.
        length: usize,
    },
}

/// Iterator over a validated compact attribute block.
#[derive(Debug, Clone)]
pub struct CompactAttributeReader<'a> {
    input: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> CompactAttributeReader<'a> {
    /// Creates a reader after validating the outer payload limit.
    ///
    /// # Errors
    ///
    /// Returns [`CompactAttributeError::PayloadTooLarge`] when the input
    /// exceeds the recovered protocol's 1,400-byte boundary.
    pub const fn new(input: &'a [u8]) -> Result<Self> {
        if input.len() > MAX_VENDOR_PAYLOAD_LENGTH {
            return Err(CompactAttributeError::PayloadTooLarge {
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
}

impl<'a> Iterator for CompactAttributeReader<'a> {
    type Item = Result<CompactAttribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.input.len() {
            return None;
        }

        let remaining = self.input.len() - self.offset;
        if remaining < 2 {
            self.failed = true;
            return Some(Err(CompactAttributeError::TruncatedHeader {
                offset: self.offset,
                remaining,
            }));
        }

        let start = self.offset;
        let kind = self.input[start];
        let length = usize::from(self.input[start + 1]);
        let value_start = start + 2;
        let available = self.input.len() - value_start;
        if available < length {
            self.failed = true;
            return Some(Err(CompactAttributeError::TruncatedValue {
                offset: start,
                kind,
                declared: length,
                remaining: available,
            }));
        }

        self.offset = value_start + length;
        Some(Ok(CompactAttribute {
            kind: AttributeKind::new(kind),
            value: &self.input[value_start..self.offset],
        }))
    }
}

/// Encoder for a bounded compact attribute block.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompactAttributeWriter {
    output: Vec<u8>,
}

impl CompactAttributeWriter {
    /// Creates an empty compact attribute writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { output: Vec::new() }
    }

    /// Appends one compact attribute.
    ///
    /// # Errors
    ///
    /// Returns an error when the value exceeds 255 bytes or the resulting
    /// block would exceed [`MAX_VENDOR_PAYLOAD_LENGTH`].
    pub fn push(&mut self, kind: AttributeKind, value: &[u8]) -> Result<()> {
        let length =
            u8::try_from(value.len()).map_err(|_error| CompactAttributeError::ValueTooLarge {
                kind: kind.raw(),
                length: value.len(),
            })?;
        let next_length = self.output.len() + 2 + value.len();
        if next_length > MAX_VENDOR_PAYLOAD_LENGTH {
            return Err(CompactAttributeError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: next_length,
            });
        }

        self.output.push(kind.raw());
        self.output.push(length);
        self.output.extend_from_slice(value);
        Ok(())
    }

    /// Returns the encoded compact block.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.output
    }

    /// Returns the current encoded length.
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
    fn round_trips_known_and_unknown_attributes() -> Result<()> {
        let mut writer = CompactAttributeWriter::new();
        writer.push(AttributeKind::REAUTH_INTERVAL, &[0, 0, 0, 60])?;
        writer.push(AttributeKind::new(0xfe), b"future")?;
        let encoded = writer.finish();
        let decoded = CompactAttributeReader::new(&encoded)?.collect::<Result<Vec<_>>>()?;

        assert_eq!(
            decoded,
            [
                CompactAttribute {
                    kind: AttributeKind::REAUTH_INTERVAL,
                    value: &[0, 0, 0, 60],
                },
                CompactAttribute {
                    kind: AttributeKind::new(0xfe),
                    value: b"future",
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn preserves_zero_length_attribute() -> Result<()> {
        let attributes = CompactAttributeReader::new(&[0x42, 0])?.collect::<Result<Vec<_>>>()?;

        assert_eq!(attributes[0].kind, AttributeKind::new(0x42));
        assert!(attributes[0].value.is_empty());
        Ok(())
    }

    #[test]
    fn reports_truncated_value_and_stops() -> Result<()> {
        let mut reader = CompactAttributeReader::new(&[0x56, 4, 0, 1])?;

        assert_eq!(
            reader.next(),
            Some(Err(CompactAttributeError::TruncatedValue {
                offset: 0,
                kind: 0x56,
                declared: 4,
                remaining: 2,
            }))
        );
        assert_eq!(reader.next(), None);
        Ok(())
    }

    #[test]
    fn enforces_value_and_block_limits() -> Result<()> {
        let mut writer = CompactAttributeWriter::new();
        assert_eq!(
            writer.push(AttributeKind::new(1), &[0; 256]),
            Err(CompactAttributeError::ValueTooLarge {
                kind: 1,
                length: 256,
            })
        );

        let value = [0; 255];
        for kind in 0..5 {
            writer.push(AttributeKind::new(kind), &value)?;
        }
        assert_eq!(
            writer.push(AttributeKind::new(5), &value),
            Err(CompactAttributeError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: 1542,
            })
        );
        Ok(())
    }

    #[test]
    fn rejects_truncated_header_and_oversized_block() -> Result<()> {
        let mut reader = CompactAttributeReader::new(&[0x56])?;
        assert_eq!(
            reader.next(),
            Some(Err(CompactAttributeError::TruncatedHeader {
                offset: 0,
                remaining: 1,
            }))
        );

        let payload = vec![0; MAX_VENDOR_PAYLOAD_LENGTH + 1];
        assert!(matches!(
            CompactAttributeReader::new(&payload),
            Err(CompactAttributeError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual,
            }) if actual == MAX_VENDOR_PAYLOAD_LENGTH + 1
        ));
        Ok(())
    }
}
