//! Structural boundary for the recovered wired Ruijie vendor trailer.
//!
//! The legacy client appends a fixed 70-byte preamble after the declared
//! EAPOL payload, followed by zero or more RADIUS Vendor-Specific Attributes.
//! The preamble contains an encoded 23-byte DHCP snapshot, two enterprise
//! magic values, a fixed-width program name, a version field, a control byte,
//! and two reserved bytes. Field semantics are deliberately not guessed here;
//! this codec only establishes the proven offsets needed to locate VSAs.

use thiserror::Error;

use crate::{
    MAX_VENDOR_PAYLOAD_LENGTH, RUIJIE_VENDOR_ID, RadiusAttributeError, RadiusAttributeReader,
};

/// Fixed byte count before the first wired RADIUS VSA.
pub const WIRED_PREAMBLE_LENGTH: usize = 70;

const FIRST_MAGIC_OFFSET: usize = 23;
const SECOND_MAGIC_OFFSET: usize = 64;
const CONTROL_FLAG_OFFSET: usize = 63;
const DHCP_SNAPSHOT_LENGTH: usize = 23;
const PROGRAM_NAME_OFFSET: usize = 27;
const PROGRAM_NAME_LENGTH: usize = 32;
const VERSION_OFFSET: usize = 59;
const VERSION_LENGTH: usize = 4;
const RESERVED_OFFSET: usize = 68;
const RESERVED_LENGTH: usize = 2;

/// Fixed-width values required before wired Ruijie RADIUS attributes.
///
/// Byte transformations inside the DHCP snapshot and program-name fields are
/// separate protocol concerns. This type only owns their proven fixed-width
/// placement and never guesses text encoding or encryption semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiredPreamble {
    encoded_dhcp_snapshot: [u8; DHCP_SNAPSHOT_LENGTH],
    encoded_program_name: [u8; PROGRAM_NAME_LENGTH],
    version: [u8; VERSION_LENGTH],
    control_flag: u8,
    reserved: [u8; RESERVED_LENGTH],
}

impl WiredPreamble {
    /// Creates a preamble from already encoded fixed-width fields.
    #[must_use]
    pub const fn new(
        encoded_dhcp_snapshot: [u8; DHCP_SNAPSHOT_LENGTH],
        encoded_program_name: [u8; PROGRAM_NAME_LENGTH],
        version: [u8; VERSION_LENGTH],
        control_flag: u8,
        reserved: [u8; RESERVED_LENGTH],
    ) -> Self {
        Self {
            encoded_dhcp_snapshot,
            encoded_program_name,
            version,
            control_flag,
            reserved,
        }
    }

    /// Encodes the complete fixed preamble with both Ruijie magic values.
    #[must_use]
    pub fn encode(&self) -> [u8; WIRED_PREAMBLE_LENGTH] {
        let mut output = [0; WIRED_PREAMBLE_LENGTH];
        output[..DHCP_SNAPSHOT_LENGTH].copy_from_slice(&self.encoded_dhcp_snapshot);
        output[FIRST_MAGIC_OFFSET..FIRST_MAGIC_OFFSET + 4]
            .copy_from_slice(&RUIJIE_VENDOR_ID.to_be_bytes());
        output[PROGRAM_NAME_OFFSET..PROGRAM_NAME_OFFSET + PROGRAM_NAME_LENGTH]
            .copy_from_slice(&self.encoded_program_name);
        output[VERSION_OFFSET..VERSION_OFFSET + VERSION_LENGTH].copy_from_slice(&self.version);
        output[CONTROL_FLAG_OFFSET] = self.control_flag;
        output[SECOND_MAGIC_OFFSET..SECOND_MAGIC_OFFSET + 4]
            .copy_from_slice(&RUIJIE_VENDOR_ID.to_be_bytes());
        output[RESERVED_OFFSET..RESERVED_OFFSET + RESERVED_LENGTH].copy_from_slice(&self.reserved);
        output
    }
}

/// Encoder for a complete wired preamble plus RADIUS VSA suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiredVendorTrailerWriter {
    preamble: WiredPreamble,
    attributes: crate::RadiusAttributeWriter,
}

impl WiredVendorTrailerWriter {
    /// Starts a trailer with a complete fixed preamble.
    #[must_use]
    pub const fn new(preamble: WiredPreamble) -> Self {
        Self {
            preamble,
            attributes: crate::RadiusAttributeWriter::new(),
        }
    }

    /// Appends one RADIUS Vendor-Specific Attribute while enforcing the
    /// complete trailer limit before mutation.
    ///
    /// # Errors
    ///
    /// Returns an error when the value cannot fit RADIUS one-byte lengths or
    /// the preamble plus accumulated attributes would exceed 1,400 bytes.
    pub fn push(
        &mut self,
        kind: crate::AttributeKind,
        value: &[u8],
    ) -> Result<(), WiredVendorTrailerError> {
        let projected = WIRED_PREAMBLE_LENGTH + self.attributes.len() + 8 + value.len();
        if projected > MAX_VENDOR_PAYLOAD_LENGTH {
            return Err(WiredVendorTrailerError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: projected,
            });
        }
        self.attributes.push(kind, value)?;
        Ok(())
    }

    /// Encodes the complete trailer.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        let attributes = self.attributes.finish();
        let mut output = Vec::with_capacity(WIRED_PREAMBLE_LENGTH + attributes.len());
        output.extend_from_slice(&self.preamble.encode());
        output.extend_from_slice(&attributes);
        output
    }

    /// Returns the complete encoded size if finished now.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        WIRED_PREAMBLE_LENGTH + self.attributes.len()
    }

    /// Returns true when no RADIUS attributes follow the mandatory preamble.
    #[must_use]
    pub const fn attributes_are_empty(&self) -> bool {
        self.attributes.is_empty()
    }
}

/// Borrowed, structurally validated wired vendor trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WiredVendorTrailer<'a> {
    preamble: &'a [u8],
    attributes: &'a [u8],
}

impl<'a> WiredVendorTrailer<'a> {
    /// Parses the fixed preamble and validates the complete following VSA
    /// stream.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized/truncated trailer, either missing
    /// enterprise magic value, or a malformed RADIUS VSA stream.
    pub fn parse(input: &'a [u8]) -> Result<Self, WiredVendorTrailerError> {
        if input.len() > MAX_VENDOR_PAYLOAD_LENGTH {
            return Err(WiredVendorTrailerError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: input.len(),
            });
        }
        if input.len() < WIRED_PREAMBLE_LENGTH {
            return Err(WiredVendorTrailerError::TruncatedPreamble {
                needed: WIRED_PREAMBLE_LENGTH,
                actual: input.len(),
            });
        }

        validate_magic(input, FIRST_MAGIC_OFFSET)?;
        validate_magic(input, SECOND_MAGIC_OFFSET)?;
        let attributes = &input[WIRED_PREAMBLE_LENGTH..];
        for attribute in RadiusAttributeReader::new(attributes)? {
            attribute?;
        }

        Ok(Self {
            preamble: &input[..WIRED_PREAMBLE_LENGTH],
            attributes,
        })
    }

    /// Returns the complete fixed preamble without interpreting unproven
    /// fields.
    #[must_use]
    pub const fn preamble(&self) -> &'a [u8] {
        self.preamble
    }

    /// Returns the recovered one-byte control flag.
    #[must_use]
    pub const fn control_flag(&self) -> u8 {
        self.preamble[CONTROL_FLAG_OFFSET]
    }

    /// Returns the opaque encoded DHCP snapshot.
    #[must_use]
    pub fn encoded_dhcp_snapshot(&self) -> &'a [u8] {
        &self.preamble[..DHCP_SNAPSHOT_LENGTH]
    }

    /// Returns the opaque fixed-width encoded program name.
    #[must_use]
    pub fn encoded_program_name(&self) -> &'a [u8] {
        &self.preamble[PROGRAM_NAME_OFFSET..PROGRAM_NAME_OFFSET + PROGRAM_NAME_LENGTH]
    }

    /// Returns the recovered four-byte client version field.
    #[must_use]
    pub fn version(&self) -> &'a [u8] {
        &self.preamble[VERSION_OFFSET..VERSION_OFFSET + VERSION_LENGTH]
    }

    /// Creates a reader for the already validated RADIUS VSA suffix.
    ///
    /// # Errors
    ///
    /// This can only fail if the crate's protocol boundary changes after the
    /// trailer was parsed; under current invariants it returns a valid reader.
    pub const fn attributes(&self) -> Result<RadiusAttributeReader<'a>, RadiusAttributeError> {
        RadiusAttributeReader::new(self.attributes)
    }

    /// Returns the complete raw VSA suffix.
    #[must_use]
    pub const fn attribute_bytes(&self) -> &'a [u8] {
        self.attributes
    }
}

/// Structural failure in a wired Ruijie trailer.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WiredVendorTrailerError {
    /// Complete trailer exceeds the recovered product boundary.
    #[error("wired vendor trailer exceeds {maximum} bytes: {actual}")]
    PayloadTooLarge {
        /// Maximum accepted byte count.
        maximum: usize,
        /// Actual byte count.
        actual: usize,
    },
    /// Trailer ends before its fixed preamble.
    #[error("wired vendor preamble is truncated: need {needed} bytes, got {actual}")]
    TruncatedPreamble {
        /// Required preamble size.
        needed: usize,
        /// Available byte count.
        actual: usize,
    },
    /// One of the two enterprise magic values does not match Ruijie.
    #[error("invalid Ruijie enterprise magic at preamble offset {offset}: 0x{actual:08x}")]
    InvalidMagic {
        /// Byte offset of the invalid magic.
        offset: usize,
        /// Decoded big-endian value.
        actual: u32,
    },
    /// RADIUS VSA suffix is malformed.
    #[error(transparent)]
    Radius(#[from] RadiusAttributeError),
}

const fn validate_magic(input: &[u8], offset: usize) -> Result<(), WiredVendorTrailerError> {
    let actual = u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]);
    if actual != RUIJIE_VENDOR_ID {
        return Err(WiredVendorTrailerError::InvalidMagic { offset, actual });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::{AttributeKind, RadiusAttributeWriter};

    use super::*;

    fn preamble(control_flag: u8) -> WiredPreamble {
        WiredPreamble::new(
            [0; DHCP_SNAPSHOT_LENGTH],
            [0; PROGRAM_NAME_LENGTH],
            [0; VERSION_LENGTH],
            control_flag,
            [0; RESERVED_LENGTH],
        )
    }

    fn valid_preamble(control_flag: u8) -> [u8; WIRED_PREAMBLE_LENGTH] {
        preamble(control_flag).encode()
    }

    #[test]
    fn locates_and_validates_radius_suffix() -> Result<(), Box<dyn Error>> {
        let mut bytes = valid_preamble(7).to_vec();
        let mut attributes = RadiusAttributeWriter::new();
        attributes.push(AttributeKind::OS_BITS, &[64])?;
        bytes.extend_from_slice(&attributes.finish());

        let trailer = WiredVendorTrailer::parse(&bytes)?;
        assert_eq!(trailer.control_flag(), 7);
        let values = trailer.attributes()?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(values[0].kind, AttributeKind::OS_BITS);
        assert_eq!(values[0].value, [64]);
        Ok(())
    }

    #[test]
    fn accepts_preamble_without_radius_attributes() -> Result<(), Box<dyn Error>> {
        let bytes = valid_preamble(0);
        let trailer = WiredVendorTrailer::parse(&bytes)?;

        assert!(trailer.attribute_bytes().is_empty());
        assert_eq!(trailer.attributes()?.next(), None);
        Ok(())
    }

    #[test]
    fn rejects_each_invalid_enterprise_magic() {
        for offset in [FIRST_MAGIC_OFFSET, SECOND_MAGIC_OFFSET] {
            let mut bytes = valid_preamble(0);
            bytes[offset + 3] = 0x12;
            assert_eq!(
                WiredVendorTrailer::parse(&bytes),
                Err(WiredVendorTrailerError::InvalidMagic {
                    offset,
                    actual: 0x0000_1312,
                })
            );
        }
    }

    #[test]
    fn rejects_truncated_preamble() {
        let bytes = vec![0; WIRED_PREAMBLE_LENGTH - 1];

        assert_eq!(
            WiredVendorTrailer::parse(&bytes),
            Err(WiredVendorTrailerError::TruncatedPreamble {
                needed: WIRED_PREAMBLE_LENGTH,
                actual: WIRED_PREAMBLE_LENGTH - 1,
            })
        );
    }

    #[test]
    fn preamble_writer_places_each_fixed_width_field() -> Result<(), Box<dyn Error>> {
        let dhcp = [0xa1; DHCP_SNAPSHOT_LENGTH];
        let program = [0xb2; PROGRAM_NAME_LENGTH];
        let version = [1, 2, 3, 4];
        let reserved = [0xc3, 0xd4];
        let bytes = WiredPreamble::new(dhcp, program, version, 9, reserved).encode();
        let trailer = WiredVendorTrailer::parse(&bytes)?;

        assert_eq!(trailer.encoded_dhcp_snapshot(), dhcp);
        assert_eq!(trailer.encoded_program_name(), program);
        assert_eq!(trailer.version(), version);
        assert_eq!(trailer.control_flag(), 9);
        assert_eq!(&bytes[RESERVED_OFFSET..], reserved);
        Ok(())
    }

    #[test]
    fn complete_writer_round_trips_and_enforces_total_limit() -> Result<(), Box<dyn Error>> {
        let mut writer = WiredVendorTrailerWriter::new(preamble(3));
        writer.push(AttributeKind::OS_BITS, &[64])?;
        let bytes = writer.finish();
        let trailer = WiredVendorTrailer::parse(&bytes)?;
        let values = trailer.attributes()?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(values[0].kind, AttributeKind::OS_BITS);

        let mut writer = WiredVendorTrailerWriter::new(preamble(0));
        for kind in 0..5 {
            writer.push(AttributeKind::new(kind), &[0; 247])?;
        }
        writer.push(AttributeKind::new(5), &[0; 47])?;
        assert_eq!(writer.encoded_len(), MAX_VENDOR_PAYLOAD_LENGTH);
        assert_eq!(
            writer.push(AttributeKind::new(6), &[]),
            Err(WiredVendorTrailerError::PayloadTooLarge {
                maximum: MAX_VENDOR_PAYLOAD_LENGTH,
                actual: MAX_VENDOR_PAYLOAD_LENGTH + 8,
            })
        );
        Ok(())
    }
}
