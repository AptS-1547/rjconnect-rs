use rjconnect_eapol::MacAddress;
use rjconnect_platform_api::{InterfaceId, InterfaceInfo, InterfaceKind, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub name: String,
    pub description: Option<String>,
    pub is_loopback: bool,
    pub is_wireless: bool,
    pub is_up: bool,
    pub mac_address: Option<MacAddress>,
}

pub fn normalize(snapshot: DeviceSnapshot) -> Result<InterfaceInfo> {
    let kind = if snapshot.is_loopback {
        InterfaceKind::Loopback
    } else if snapshot.is_wireless {
        InterfaceKind::Wifi
    } else if is_tunnel_name(&snapshot.name) {
        InterfaceKind::Tunnel
    } else {
        InterfaceKind::Ethernet
    };
    let display_name = snapshot
        .description
        .filter(|description| !description.is_empty())
        .unwrap_or_else(|| snapshot.name.clone());

    Ok(InterfaceInfo {
        id: InterfaceId::new(snapshot.name)?,
        display_name,
        kind,
        mac_address: snapshot.mac_address,
        is_up: snapshot.is_up,
    })
}

pub fn mac_from_link_data(
    data: &[u8],
    name_length: usize,
    address_length: usize,
) -> Option<MacAddress> {
    if address_length != 6 {
        return None;
    }
    let address_end = name_length.checked_add(address_length)?;
    let address = data.get(name_length..address_end)?;
    let mut octets = [0; 6];
    octets.copy_from_slice(address);
    Some(MacAddress::new(octets))
}

fn is_tunnel_name(name: &str) -> bool {
    name.starts_with("utun") || name.starts_with("ipsec") || name.starts_with("ppp")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(name: &str) -> DeviceSnapshot {
        DeviceSnapshot {
            name: name.to_owned(),
            description: None,
            is_loopback: false,
            is_wireless: false,
            is_up: true,
            mac_address: None,
        }
    }

    #[test]
    fn classifies_tunnel_without_assuming_mac_address() -> Result<()> {
        let interface = normalize(snapshot("utun7"))?;

        assert_eq!(interface.kind, InterfaceKind::Tunnel);
        assert_eq!(interface.mac_address, None);
        assert_eq!(interface.display_name, "utun7");
        assert!(!interface.supports_wired_eapol());
        Ok(())
    }

    #[test]
    fn pcap_flags_take_precedence_over_name_heuristics() -> Result<()> {
        let mut wifi = snapshot("en0");
        wifi.is_wireless = true;
        wifi.description = Some("Wi-Fi".to_owned());
        let wifi = normalize(wifi)?;

        assert_eq!(wifi.kind, InterfaceKind::Wifi);
        assert_eq!(wifi.display_name, "Wi-Fi");
        Ok(())
    }

    #[test]
    fn parses_link_address_after_variable_length_name() {
        let data = [b'e', b'n', b'0', 2, 3, 4, 5, 6, 7];

        assert_eq!(
            mac_from_link_data(&data, 3, 6),
            Some(MacAddress::new([2, 3, 4, 5, 6, 7]))
        );
        assert_eq!(mac_from_link_data(&data, 3, 5), None);
        assert_eq!(mac_from_link_data(&data[..8], 3, 6), None);
    }
}
