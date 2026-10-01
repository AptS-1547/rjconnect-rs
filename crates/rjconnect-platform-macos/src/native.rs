#![expect(
    unsafe_code,
    reason = "macOS getifaddrs/AF_LINK traversal requires a small audited FFI boundary"
)]

use std::{collections::HashMap, ffi::CStr, mem::offset_of, ptr, slice};

use pcap::{Active, Capture, Device, Error as PcapError, IfFlags, Linktype};
use rjconnect_eapol::MacAddress;
use rjconnect_platform_api::{
    EthernetLink, FrameChannel, FrameChannelConfig, InterfaceId, InterfaceInfo,
    MAX_ETHERNET_FRAME_LENGTH, MIN_ETHERNET_FRAME_LENGTH, PlatformError, ReceiveOutcome, Result,
};

use crate::normalize::{DeviceSnapshot, mac_from_link_data, normalize};

const EAPOL_FILTER: &str = "ether proto 0x888e";
const CAPTURE_BUFFER_LENGTH: i32 = 1_048_576;

/// macOS libpcap/BPF Ethernet provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosEthernet;

/// Active bounded macOS Ethernet channel.
pub struct MacosFrameChannel {
    capture: Capture<Active>,
}

impl EthernetLink for MacosEthernet {
    type Channel = MacosFrameChannel;

    fn interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        let mac_addresses = mac_addresses()?;
        Device::list()
            .map_err(|error| map_pcap_error("enumerate interfaces", &error))?
            .into_iter()
            .map(|device| {
                let is_up =
                    device.flags.contains(IfFlags::UP) && device.flags.contains(IfFlags::RUNNING);
                normalize(DeviceSnapshot {
                    mac_address: mac_addresses.get(&device.name).copied(),
                    name: device.name,
                    description: device.desc,
                    is_loopback: device.flags.is_loopback(),
                    is_wireless: device.flags.is_wireless(),
                    is_up,
                })
            })
            .collect()
    }

    fn open(&self, interface: &InterfaceId, config: &FrameChannelConfig) -> Result<Self::Channel> {
        let device = Device::list()
            .map_err(|error| map_pcap_error("enumerate interfaces", &error))?
            .into_iter()
            .find(|device| device.name == interface.as_str())
            .ok_or_else(|| PlatformError::InterfaceUnavailable {
                interface: interface.as_str().to_owned(),
            })?;
        let snapshot_length = i32::try_from(config.snapshot_length()).map_err(|_error| {
            PlatformError::InvalidSnapshotLength {
                actual: config.snapshot_length(),
                minimum: FrameChannelConfig::MIN_SNAPSHOT_LENGTH,
                maximum: FrameChannelConfig::MAX_SNAPSHOT_LENGTH,
            }
        })?;
        let timeout_millis =
            i32::try_from(config.read_timeout().as_millis()).map_err(|_error| {
                PlatformError::InvalidReadTimeout {
                    actual: config.read_timeout(),
                    minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
                    maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
                }
            })?;
        let mut capture = Capture::from_device(device)
            .map_err(|error| map_pcap_error("create capture", &error))?
            .snaplen(snapshot_length)
            .timeout(timeout_millis)
            .promisc(config.promiscuous())
            .immediate_mode(true)
            .buffer_size(CAPTURE_BUFFER_LENGTH)
            .open()
            .map_err(|error| map_pcap_error("activate capture", &error))?;
        if capture.get_datalink() != Linktype::ETHERNET {
            return Err(PlatformError::UnsupportedCapability {
                capability: "non-Ethernet libpcap link type",
            });
        }
        capture
            .filter(EAPOL_FILTER, true)
            .map_err(|error| map_pcap_error("install EAPOL filter", &error))?;
        Ok(MacosFrameChannel { capture })
    }
}

impl FrameChannel for MacosFrameChannel {
    fn receive(&mut self) -> Result<ReceiveOutcome> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(ReceiveOutcome::Frame(packet.data.to_vec())),
            Err(PcapError::TimeoutExpired) => Ok(ReceiveOutcome::Timeout),
            Err(error) => Err(map_pcap_error("receive frame", &error)),
        }
    }

    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if !(MIN_ETHERNET_FRAME_LENGTH..=MAX_ETHERNET_FRAME_LENGTH).contains(&frame.len()) {
            return Err(PlatformError::InvalidFrameLength {
                actual: frame.len(),
                minimum: MIN_ETHERNET_FRAME_LENGTH,
                maximum: MAX_ETHERNET_FRAME_LENGTH,
            });
        }
        self.capture
            .sendpacket(frame)
            .map_err(|error| map_pcap_error("send frame", &error))
    }
}

fn map_pcap_error(operation: &'static str, error: &PcapError) -> PlatformError {
    let message = error.to_string();
    let lowercase = message.to_ascii_lowercase();
    if lowercase.contains("permission denied") || lowercase.contains("not permitted") {
        PlatformError::PermissionDenied { operation }
    } else {
        PlatformError::OperationFailed { operation, message }
    }
}

fn mac_addresses() -> Result<HashMap<String, MacAddress>> {
    let mut head = ptr::null_mut();
    // SAFETY: `getifaddrs` initializes `head` on success. The returned list is
    // guarded immediately and freed exactly once by `IfAddrsGuard::drop`.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(PlatformError::OperationFailed {
            operation: "enumerate link addresses",
            message: std::io::Error::last_os_error().to_string(),
        });
    }
    let guard = IfAddrsGuard(head);
    let mut output = HashMap::new();
    let mut current = guard.0;
    while !current.is_null() {
        // SAFETY: every node belongs to the live getifaddrs list held by
        // `guard`; null address/name pointers are checked before dereference.
        unsafe {
            let entry = &*current;
            if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null() {
                let address = entry.ifa_addr;
                if i32::from((*address).sa_family) == libc::AF_LINK {
                    let link = address.cast::<libc::sockaddr_dl>();
                    let total_length = usize::from((*link).sdl_len);
                    let data_offset = offset_of!(libc::sockaddr_dl, sdl_data);
                    if total_length >= data_offset {
                        let raw = slice::from_raw_parts(
                            link.cast::<u8>().add(data_offset),
                            total_length - data_offset,
                        );
                        if let Some(mac) = mac_from_link_data(
                            raw,
                            usize::from((*link).sdl_nlen),
                            usize::from((*link).sdl_alen),
                        ) {
                            let name = CStr::from_ptr(entry.ifa_name)
                                .to_string_lossy()
                                .into_owned();
                            output.insert(name, mac);
                        }
                    }
                }
            }
            current = entry.ifa_next;
        }
    }
    Ok(output)
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was returned by one successful `getifaddrs`
            // call and this guard is its sole owner.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rjconnect_platform_api::InterfaceKind;

    use super::*;

    #[test]
    fn native_enumeration_returns_unique_nonempty_ids() -> Result<()> {
        let interfaces = MacosEthernet.interfaces()?;
        assert!(!interfaces.is_empty());

        let mut ids = HashSet::new();
        for interface in &interfaces {
            assert!(!interface.id.as_str().is_empty());
            assert!(ids.insert(interface.id.as_str()));
        }
        assert!(
            interfaces
                .iter()
                .any(|interface| interface.kind == InterfaceKind::Loopback)
        );
        Ok(())
    }

    #[test]
    fn permission_errors_are_classified_without_exposing_backend_variant() {
        assert_eq!(
            map_pcap_error(
                "activate capture",
                &PcapError::PcapError("BIOCSETIF: Permission denied".to_owned()),
            ),
            PlatformError::PermissionDenied {
                operation: "activate capture",
            }
        );
    }
}
