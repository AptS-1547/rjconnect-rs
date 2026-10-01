//! Cross-crate test for the complete wired Identity exchange.
//!
//! The fixture enters as raw Ethernet bytes, crosses the Ethernet, EAPOL and
//! EAP codecs, drives the pure state machine, and is encoded back to a raw
//! Ethernet response. Platform capture code is intentionally not involved.

use std::error::Error;

use rjconnect_auth::{
    AuthEffect, AuthEvent, AuthMachine, AuthState, Credentials, IncomingEap, SessionPolicy,
};
use rjconnect_eapol::{
    ETHERTYPE_EAPOL, EapCode, EapMethod, EapPacket, EapolPacket, EapolPacketType, EthernetFrame,
    MacAddress,
};

#[test]
fn raw_identity_request_produces_wire_response_and_accepts_success() -> Result<(), Box<dyn Error>> {
    let client_mac = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
    let authenticator_mac = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
    let request_eap = EapPacket {
        code: EapCode::Request,
        identifier: 0x2a,
        method: Some(EapMethod::Identity),
        payload: &[],
        trailing: &[],
    }
    .encode()?;
    let request_eapol = EapolPacket {
        version: 1,
        packet_type: EapolPacketType::EapPacket,
        payload: &request_eap,
        trailing: &[],
    }
    .encode()?;
    let request_wire = EthernetFrame {
        destination: client_mac,
        source: authenticator_mac,
        vlan_tags: Vec::new(),
        ether_type: ETHERTYPE_EAPOL,
        payload: &request_eapol,
    }
    .encode()?;

    let frame = EthernetFrame::parse(&request_wire)?;
    assert_eq!(frame.ether_type, ETHERTYPE_EAPOL);
    let eapol = EapolPacket::parse(frame.payload)?;
    assert_eq!(eapol.packet_type, EapolPacketType::EapPacket);
    let eap = EapPacket::parse(eapol.payload)?;

    let credentials = Credentials::new(b"student".to_vec(), b"secret".to_vec())?;
    let mut machine = AuthMachine::new(credentials, SessionPolicy::default());
    machine.handle(AuthEvent::Start)?;
    let effects = machine.handle(AuthEvent::Eap(IncomingEap::from_packet(&eap)))?;
    let Some(response_eap) = effects.iter().find_map(|effect| match effect {
        AuthEffect::SendEap { packet, .. } => Some(packet),
        _ => None,
    }) else {
        return Err("state machine did not emit an EAP response".into());
    };
    let response_eapol = EapolPacket {
        version: eapol.version,
        packet_type: EapolPacketType::EapPacket,
        payload: response_eap,
        trailing: &[],
    }
    .encode()?;
    let response_wire = EthernetFrame {
        destination: authenticator_mac,
        source: client_mac,
        vlan_tags: frame.vlan_tags,
        ether_type: ETHERTYPE_EAPOL,
        payload: &response_eapol,
    }
    .encode()?;

    let encoded_frame = EthernetFrame::parse(&response_wire)?;
    assert_eq!(encoded_frame.destination, authenticator_mac);
    assert_eq!(encoded_frame.source, client_mac);
    let encoded_eapol = EapolPacket::parse(encoded_frame.payload)?;
    let encoded_eap = EapPacket::parse(encoded_eapol.payload)?;
    assert_eq!(encoded_eap.code, EapCode::Response);
    assert_eq!(encoded_eap.identifier, 0x2a);
    assert_eq!(encoded_eap.method, Some(EapMethod::Identity));
    assert_eq!(encoded_eap.payload, b"student");

    let success = IncomingEap {
        code: EapCode::Success,
        identifier: 0x2a,
        method: None,
        payload: Vec::new(),
    };
    let success_effects = machine.handle(AuthEvent::Eap(success))?;
    assert!(success_effects.contains(&AuthEffect::Authenticated));
    assert_eq!(machine.state(), AuthState::Authenticated);
    Ok(())
}
