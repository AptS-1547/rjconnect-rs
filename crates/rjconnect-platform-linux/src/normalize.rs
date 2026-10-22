use rjconnect_eapol::MacAddress;
use rjconnect_platform_api::{InterfaceId, InterfaceInfo, InterfaceKind, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceNature {
    PhysicalEthernet,
    Wireless,
    Loopback,
    PointToPoint,
    VirtualOrUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub name: String,
    pub mac_address: Option<MacAddress>,
    pub nature: DeviceNature,
    pub is_up: bool,
}

pub fn normalize(snapshot: DeviceSnapshot) -> Result<InterfaceInfo> {
    let kind = match snapshot.nature {
        DeviceNature::Loopback => InterfaceKind::Loopback,
        DeviceNature::Wireless => InterfaceKind::Wifi,
        DeviceNature::PointToPoint => InterfaceKind::Tunnel,
        DeviceNature::PhysicalEthernet => InterfaceKind::Ethernet,
        DeviceNature::VirtualOrUnknown => InterfaceKind::Other,
    };

    Ok(InterfaceInfo {
        id: InterfaceId::new(snapshot.name.clone())?,
        display_name: snapshot.name,
        kind,
        mac_address: snapshot.mac_address,
        is_up: snapshot.is_up,
    })
}

#[cfg(test)]
mod tests {
    use rjconnect_platform_api::InterfaceKind;

    use super::*;

    fn snapshot(name: &str) -> DeviceSnapshot {
        DeviceSnapshot {
            name: name.to_owned(),
            mac_address: Some(MacAddress::new([2, 3, 4, 5, 6, 7])),
            nature: DeviceNature::PhysicalEthernet,
            is_up: true,
        }
    }

    #[test]
    fn physical_ethernet_is_wired_eapol_candidate() -> Result<()> {
        let interface = normalize(snapshot("enp3s0"))?;

        assert_eq!(interface.kind, InterfaceKind::Ethernet);
        assert!(interface.supports_wired_eapol());
        Ok(())
    }

    #[test]
    fn non_physical_interfaces_are_classified_without_becoming_wired_candidates() -> Result<()> {
        let loopback = DeviceSnapshot {
            mac_address: None,
            nature: DeviceNature::Loopback,
            ..snapshot("lo")
        };

        let wireless = DeviceSnapshot {
            nature: DeviceNature::Wireless,
            ..snapshot("wlan0")
        };

        let tunnel = DeviceSnapshot {
            mac_address: None,
            nature: DeviceNature::PointToPoint,
            ..snapshot("tun0")
        };

        let bridge = DeviceSnapshot {
            nature: DeviceNature::VirtualOrUnknown,
            ..snapshot("br0")
        };

        for (device, expected) in [
            (loopback, InterfaceKind::Loopback),
            (wireless, InterfaceKind::Wifi),
            (tunnel, InterfaceKind::Tunnel),
            (bridge, InterfaceKind::Other),
        ] {
            let interface = normalize(device)?;
            assert_eq!(interface.kind, expected);
            assert!(!interface.supports_wired_eapol());
        }
        Ok(())
    }
}
