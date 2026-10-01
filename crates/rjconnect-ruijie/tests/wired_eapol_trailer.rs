//! Verifies the recovered wired layout where a fixed Ruijie preamble and its
//! RADIUS VSAs follow the declared EAPOL payload instead of being counted by
//! the EAP/EAPOL lengths.

use std::error::Error;

use rjconnect_eapol::{EapMethod, EapPacket, EapolPacket, EapolPacketType};
use rjconnect_ruijie::{
    AttributeKind, RUIJIE_VENDOR_ID, RadiusAttributeWriter, WIRED_PREAMBLE_LENGTH,
    WiredVendorTrailer,
};

#[test]
fn radius_vendor_attributes_round_trip_as_eapol_trailer() -> Result<(), Box<dyn Error>> {
    let eap = EapPacket::response(7, EapMethod::Identity, b"student").encode()?;
    let mut attributes = RadiusAttributeWriter::new();
    attributes.push(AttributeKind::new(0x35), &[3])?;
    attributes.push(AttributeKind::OS_BITS, &[64])?;
    let mut trailer = vec![0; WIRED_PREAMBLE_LENGTH];
    trailer[23..27].copy_from_slice(&RUIJIE_VENDOR_ID.to_be_bytes());
    trailer[64..68].copy_from_slice(&RUIJIE_VENDOR_ID.to_be_bytes());
    trailer.extend_from_slice(&attributes.finish());
    let eapol = EapolPacket {
        version: 1,
        packet_type: EapolPacketType::EapPacket,
        payload: &eap,
        trailing: &trailer,
    };
    let wire = eapol.encode_with_trailing()?;

    let decoded_eapol = EapolPacket::parse(&wire)?;
    assert_eq!(decoded_eapol.payload, eap);
    assert_eq!(decoded_eapol.trailing, trailer);
    let decoded_eap = EapPacket::parse(decoded_eapol.payload)?;
    assert_eq!(decoded_eap.payload, b"student");
    let decoded_trailer = WiredVendorTrailer::parse(decoded_eapol.trailing)?;
    let decoded_attributes = decoded_trailer
        .attributes()?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(decoded_attributes.len(), 2);
    assert_eq!(decoded_attributes[0].kind, AttributeKind::new(0x35));
    assert_eq!(decoded_attributes[0].value, [3]);
    assert_eq!(decoded_attributes[1].kind, AttributeKind::OS_BITS);
    assert_eq!(decoded_attributes[1].value, [64]);
    Ok(())
}
