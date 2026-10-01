//! Ethernet II framing used by wired 802.1X.
//!
//! Wire layout without VLAN tags:
//!
//! ```text
//!  0               6              12      14
//!  +---------------+---------------+-------+-----------------
//!  | destination   | source        | type  | payload
//!  +---------------+---------------+-------+-----------------
//! ```
//!
//! Each VLAN tag inserts a two-byte TCI followed by the next `EtherType`.
//! The parser intentionally accepts at most `QinQ` depth two: deeper stacks are
//! outside the product contract and rejected rather than silently flattened.

use crate::error::{CodecError, Result};

const ETHERNET_HEADER_LENGTH: usize = 14;
const VLAN_TPID_8021Q: u16 = 0x8100;
const VLAN_TPID_8021AD: u16 = 0x88a8;
const MAX_VLAN_DEPTH: usize = 2;

/// A six-byte IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Standard PAE group address used by IEEE 802.1X.
    pub const PAE_GROUP: Self = Self([0x01, 0x80, 0xc2, 0x00, 0x00, 0x03]);

    /// Group address used by legacy Ruijie authenticators.
    pub const RUIJIE_GROUP: Self = Self([0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03]);

    /// Creates a MAC address from its wire representation.
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Returns the wire representation.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

/// An IEEE 802.1Q or IEEE 802.1ad tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    tpid: u16,
    tci: u16,
}

impl VlanTag {
    /// Creates a validated VLAN tag.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::InvalidVlanTpid`] when `tpid` is not IEEE
    /// 802.1Q (`0x8100`) or IEEE 802.1ad (`0x88a8`).
    pub const fn new(tpid: u16, tci: u16) -> Result<Self> {
        if is_vlan_tpid(tpid) {
            Ok(Self { tpid, tci })
        } else {
            Err(CodecError::InvalidVlanTpid { tpid })
        }
    }

    /// Returns the tag protocol identifier.
    #[must_use]
    pub const fn tpid(self) -> u16 {
        self.tpid
    }

    /// Returns the tag control information.
    #[must_use]
    pub const fn tci(self) -> u16 {
        self.tci
    }
}

/// A borrowed Ethernet II frame with up to two VLAN tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    /// Destination MAC address.
    pub destination: MacAddress,
    /// Source MAC address.
    pub source: MacAddress,
    /// VLAN tags from outermost to innermost.
    pub vlan_tags: Vec<VlanTag>,
    /// Inner `EtherType`.
    pub ether_type: u16,
    /// Ethernet payload.
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Parses an Ethernet II frame.
    ///
    /// # Errors
    ///
    /// Returns an error for truncated headers or more than two nested VLAN
    /// tags. IEEE 802.3 length-framed packets are left to higher layers.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        if input.len() < ETHERNET_HEADER_LENGTH {
            return Err(CodecError::Truncated {
                layer: "Ethernet",
                needed: ETHERNET_HEADER_LENGTH,
                actual: input.len(),
            });
        }

        let destination = MacAddress::new(copy_array(&input[0..6]));
        let source = MacAddress::new(copy_array(&input[6..12]));
        let mut cursor = 14;
        let mut ether_type = u16::from_be_bytes(copy_array(&input[12..14]));
        let mut vlan_tags = Vec::new();

        while is_vlan_tpid(ether_type) {
            if vlan_tags.len() == MAX_VLAN_DEPTH {
                return Err(CodecError::VlanNestingTooDeep {
                    maximum: MAX_VLAN_DEPTH,
                });
            }
            if input.len() < cursor + 4 {
                return Err(CodecError::Truncated {
                    layer: "Ethernet VLAN",
                    needed: cursor + 4,
                    actual: input.len(),
                });
            }

            let tci = u16::from_be_bytes(copy_array(&input[cursor..cursor + 2]));
            vlan_tags.push(VlanTag {
                tpid: ether_type,
                tci,
            });
            ether_type = u16::from_be_bytes(copy_array(&input[cursor + 2..cursor + 4]));
            cursor += 4;
        }

        Ok(Self {
            destination,
            source,
            vlan_tags,
            ether_type,
            payload: &input[cursor..],
        })
    }

    /// Encodes the frame into a new byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error when more than two VLAN tags are supplied or a tag
    /// contains an unsupported TPID.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.vlan_tags.len() > MAX_VLAN_DEPTH {
            return Err(CodecError::VlanNestingTooDeep {
                maximum: MAX_VLAN_DEPTH,
            });
        }

        let mut output = Vec::with_capacity(
            ETHERNET_HEADER_LENGTH + self.vlan_tags.len() * 4 + self.payload.len(),
        );
        output.extend_from_slice(&self.destination.octets());
        output.extend_from_slice(&self.source.octets());

        for tag in &self.vlan_tags {
            if !is_vlan_tpid(tag.tpid) {
                return Err(CodecError::InvalidVlanTpid { tpid: tag.tpid });
            }
            output.extend_from_slice(&tag.tpid.to_be_bytes());
            output.extend_from_slice(&tag.tci.to_be_bytes());
        }
        output.extend_from_slice(&self.ether_type.to_be_bytes());
        output.extend_from_slice(self.payload);
        Ok(output)
    }
}

const fn is_vlan_tpid(value: u16) -> bool {
    value == VLAN_TPID_8021Q || value == VLAN_TPID_8021AD
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(bytes);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ETHERTYPE_EAPOL;

    #[test]
    fn parses_and_round_trips_untagged_frame() -> Result<()> {
        let bytes = [
            1, 128, 194, 0, 0, 3, 2, 3, 4, 5, 6, 7, 0x88, 0x8e, 1, 1, 0, 0,
        ];
        let frame = EthernetFrame::parse(&bytes)?;

        assert_eq!(frame.destination, MacAddress::PAE_GROUP);
        assert_eq!(frame.source, MacAddress::new([2, 3, 4, 5, 6, 7]));
        assert_eq!(frame.ether_type, ETHERTYPE_EAPOL);
        assert!(frame.vlan_tags.is_empty());
        assert_eq!(frame.payload, [1, 1, 0, 0]);
        assert_eq!(frame.encode()?, bytes);
        Ok(())
    }

    #[test]
    fn parses_qinq_tags_in_wire_order() -> Result<()> {
        let bytes = [
            1, 128, 194, 0, 0, 3, 2, 3, 4, 5, 6, 7, 0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x20, 0x01,
            0x88, 0x8e, 1, 1, 0, 0,
        ];
        let frame = EthernetFrame::parse(&bytes)?;

        assert_eq!(frame.vlan_tags.len(), 2);
        assert_eq!(frame.vlan_tags[0], VlanTag::new(0x88a8, 100)?);
        assert_eq!(frame.vlan_tags[1], VlanTag::new(0x8100, 0x2001)?);
        assert_eq!(frame.ether_type, ETHERTYPE_EAPOL);
        assert_eq!(frame.encode()?, bytes);
        Ok(())
    }

    #[test]
    fn rejects_truncated_vlan_header() {
        let bytes = [1, 128, 194, 0, 0, 3, 2, 3, 4, 5, 6, 7, 0x81, 0x00, 0x00];

        assert_eq!(
            EthernetFrame::parse(&bytes),
            Err(CodecError::Truncated {
                layer: "Ethernet VLAN",
                needed: 18,
                actual: 15,
            })
        );
    }

    #[test]
    fn rejects_more_than_two_vlan_tags() {
        let bytes = [
            1, 128, 194, 0, 0, 3, 2, 3, 4, 5, 6, 7, 0x81, 0x00, 0, 1, 0x81, 0, 0, 2, 0x81, 0, 0, 3,
            0x88, 0x8e,
        ];

        assert_eq!(
            EthernetFrame::parse(&bytes),
            Err(CodecError::VlanNestingTooDeep { maximum: 2 })
        );
    }

    #[test]
    fn rejects_every_truncated_base_header_length() {
        for length in 0..ETHERNET_HEADER_LENGTH {
            let bytes = vec![0; length];
            assert_eq!(
                EthernetFrame::parse(&bytes),
                Err(CodecError::Truncated {
                    layer: "Ethernet",
                    needed: ETHERNET_HEADER_LENGTH,
                    actual: length,
                })
            );
        }
    }

    #[test]
    fn rejects_non_vlan_tpid_in_constructor() {
        assert_eq!(
            VlanTag::new(ETHERTYPE_EAPOL, 1),
            Err(CodecError::InvalidVlanTpid {
                tpid: ETHERTYPE_EAPOL,
            })
        );
    }
}
