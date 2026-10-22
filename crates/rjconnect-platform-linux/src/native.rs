use std::{
    collections::HashMap,
    ffi::{CStr, CString, OsString},
    fs, io,
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::ffi::OsStringExt,
    path::Path,
    ptr,
    time::{Duration, Instant},
};

use libc::{BPF_H, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, sock_filter};
use rjconnect_eapol::MacAddress;
use rjconnect_platform_api::{
    EthernetLink, FrameChannel, FrameChannelConfig, InterfaceId, InterfaceInfo, InterfaceKind,
    MAX_ETHERNET_FRAME_LENGTH, MIN_ETHERNET_FRAME_LENGTH, PlatformError, ReceiveOutcome, Result,
};

use crate::{
    error::map_io_error,
    normalize::{DeviceNature, DeviceSnapshot, normalize},
};

const EAPOL_ETHERTYPE: u32 = 0x888e;
#[cfg(test)]
const EAPOL_ETHERTYPE_WIRE: u16 = 0x888e;
const VLAN_TPID_8021Q: u32 = 0x8100;
const VLAN_TPID_8021Q_WIRE: u16 = 0x8100;
const VLAN_TPID_8021AD: u32 = 0x88a8;
#[cfg(test)]
const VLAN_TPID_8021AD_WIRE: u16 = 0x88a8;
const ETH_P_ALL: u16 = 0x0003;
const LOAD_ETHERTYPE: u16 = bpf_opcode(BPF_LD | BPF_H | libc::BPF_ABS);
const COMPARE_IMMEDIATE: u16 = bpf_opcode(BPF_JMP | BPF_JEQ | BPF_K);
const RETURN_IMMEDIATE: u16 = bpf_opcode(BPF_RET | BPF_K);

/// Linux `AF_PACKET` Ethernet provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxEthernet;

/// Active bounded Linux Ethernet channel.
pub struct LinuxFrameChannel {
    socket: OwnedFd,
    interface: String,
    ifindex: i32,
    local_mac: MacAddress,
    snapshot_length: usize,
    read_timeout: Duration,
}

impl EthernetLink for LinuxEthernet {
    type Channel = LinuxFrameChannel;

    fn interfaces(&self) -> Result<Vec<InterfaceInfo>> {
        enumerate_interfaces()
    }

    fn open(&self, interface: &InterfaceId, config: &FrameChannelConfig) -> Result<Self::Channel> {
        let interface_name = interface.as_str();
        let interface_info = enumerate_interfaces()?
            .into_iter()
            .find(|candidate| candidate.id == *interface)
            .ok_or_else(|| PlatformError::InterfaceUnavailable {
                interface: interface_name.to_owned(),
            })?;

        if interface_info.kind != InterfaceKind::Ethernet {
            return Err(PlatformError::UnsupportedCapability {
                capability: "non-physical Ethernet wired interface",
            });
        }
        let Some(local_mac) = interface_info.mac_address else {
            return Err(PlatformError::UnsupportedCapability {
                capability: "Ethernet interface without a MAC address",
            });
        };
        if !interface_info.is_up {
            return Err(PlatformError::InterfaceUnavailable {
                interface: interface_name.to_owned(),
            });
        }

        let raw_interface_name = decode_interface_name(interface_name)?;
        let interface_c =
            CString::new(raw_interface_name).map_err(|_error| PlatformError::InvalidInterfaceId)?;
        // SAFETY: `interface_c` is a valid NUL-terminated interface name.
        let raw_ifindex = unsafe { libc::if_nametoindex(interface_c.as_ptr()) };
        if raw_ifindex == 0 {
            return Err(PlatformError::InterfaceUnavailable {
                interface: interface_name.to_owned(),
            });
        }
        let ifindex =
            i32::try_from(raw_ifindex).map_err(|_error| PlatformError::OperationFailed {
                operation: "resolve interface index",
                message: "interface index exceeds AF_PACKET range".to_owned(),
            })?;

        let socket = create_packet_socket(interface_name)?;
        bind_packet_socket(socket.as_raw_fd(), interface_name, ifindex)?;
        enable_packet_auxdata(socket.as_raw_fd(), interface_name)?;
        set_receive_timeout(socket.as_raw_fd(), interface_name, config.read_timeout())?;
        attach_eapol_filter(socket.as_raw_fd(), interface_name, config.snapshot_length())?;
        if config.promiscuous() {
            enable_promiscuous(socket.as_raw_fd(), interface_name, ifindex)?;
        }

        Ok(LinuxFrameChannel {
            socket,
            interface: interface_name.to_owned(),
            ifindex,
            local_mac,
            snapshot_length: config.snapshot_length(),
            read_timeout: config.read_timeout(),
        })
    }
}

impl FrameChannel for LinuxFrameChannel {
    #[expect(
        clippy::useless_conversion,
        reason = "msghdr ancillary-length field width varies by target"
    )]
    fn receive(&mut self) -> Result<ReceiveOutcome> {
        set_receive_timeout(self.socket.as_raw_fd(), &self.interface, self.read_timeout)?;
        let deadline = Instant::now().checked_add(self.read_timeout).ok_or(
            PlatformError::InvalidReadTimeout {
                actual: self.read_timeout,
                minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
                maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
            },
        )?;

        loop {
            let mut buffer = vec![0_u8; self.snapshot_length];
            let mut iovec = libc::iovec {
                iov_base: buffer.as_mut_ptr().cast(),
                iov_len: buffer.len(),
            };
            let mut source: libc::sockaddr_ll = unsafe { zeroed() };
            let mut control = [0 as libc::c_long; 32];
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_name = (&raw mut source).cast();
            message.msg_namelen = socket_address_length::<libc::sockaddr_ll>("receive frame")?;
            message.msg_iov = &raw mut iovec;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = size_of_val(&control).try_into().map_err(|_error| {
                PlatformError::OperationFailed {
                    operation: "receive frame",
                    message: "ancillary buffer length exceeds platform range".to_owned(),
                }
            })?;

            // SAFETY: all message pointers reference initialized storage for the
            // duration of the call, and the receive buffer is uniquely borrowed.
            let received = unsafe {
                libc::recvmsg(self.socket.as_raw_fd(), &raw mut message, libc::MSG_TRUNC)
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                match error.kind() {
                    io::ErrorKind::Interrupted => {
                        if !self.reset_timeout(deadline)? {
                            return Ok(ReceiveOutcome::Timeout);
                        }
                        continue;
                    }
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        return Ok(ReceiveOutcome::Timeout);
                    }
                    _ => {
                        return Err(map_native_io_error(
                            "receive frame",
                            &self.interface,
                            &error,
                        ));
                    }
                }
            }

            let received_length =
                usize::try_from(received).map_err(|_error| PlatformError::OperationFailed {
                    operation: "receive frame",
                    message: "received byte count exceeds platform range".to_owned(),
                })?;
            if message.msg_flags & libc::MSG_TRUNC != 0 || received_length > buffer.len() {
                return Err(PlatformError::OperationFailed {
                    operation: "receive frame",
                    message: "received frame exceeded configured snapshot length".to_owned(),
                });
            }
            buffer.truncate(received_length);
            if let Some(auxdata) = vlan_metadata(&message) {
                restore_vlan_tag(&mut buffer, &auxdata, self.snapshot_length)?;
            }

            let is_own_frame = buffer
                .get(6..12)
                .is_some_and(|source_mac| source_mac == self.local_mac.octets());
            if source.sll_pkttype == libc::PACKET_OUTGOING || is_own_frame {
                if !self.reset_timeout(deadline)? {
                    return Ok(ReceiveOutcome::Timeout);
                }
                continue;
            }

            return Ok(ReceiveOutcome::Frame(buffer));
        }
    }

    fn send(&mut self, frame: &[u8]) -> Result<()> {
        validate_outbound_frame_length(frame.len())?;

        let address = packet_address(self.ifindex)?;
        // SAFETY: `frame` and `address` remain valid for the syscall duration.
        let sent = unsafe {
            libc::sendto(
                self.socket.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                libc::MSG_NOSIGNAL,
                (&raw const address).cast(),
                socket_address_length::<libc::sockaddr_ll>("send frame")?,
            )
        };
        if sent < 0 {
            return Err(map_native_io_error(
                "send frame",
                &self.interface,
                &io::Error::last_os_error(),
            ));
        }
        if usize::try_from(sent).ok() != Some(frame.len()) {
            return Err(PlatformError::OperationFailed {
                operation: "send frame",
                message: "AF_PACKET accepted only part of the frame".to_owned(),
            });
        }
        Ok(())
    }
}

fn validate_outbound_frame_length(length: usize) -> Result<()> {
    if (MIN_ETHERNET_FRAME_LENGTH..=MAX_ETHERNET_FRAME_LENGTH).contains(&length) {
        Ok(())
    } else {
        Err(PlatformError::InvalidFrameLength {
            actual: length,
            minimum: MIN_ETHERNET_FRAME_LENGTH,
            maximum: MAX_ETHERNET_FRAME_LENGTH,
        })
    }
}

impl LinuxFrameChannel {
    fn reset_timeout(&self, deadline: Instant) -> Result<bool> {
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        let remaining = deadline.duration_since(now);
        set_receive_timeout(self.socket.as_raw_fd(), &self.interface, remaining)?;
        Ok(true)
    }
}

#[derive(Debug, Default)]
struct InterfaceBuilder {
    flags: u32,
    hardware_type: u16,
    mac_address: Option<MacAddress>,
}

fn enumerate_interfaces() -> Result<Vec<InterfaceInfo>> {
    let mut head = ptr::null_mut();
    // SAFETY: `getifaddrs` initializes `head` on success. The returned list is
    // guarded immediately and freed exactly once by `IfAddrsGuard::drop`.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(PlatformError::OperationFailed {
            operation: "enumerate interfaces",
            message: io::Error::last_os_error().to_string(),
        });
    }
    let guard = IfAddrsGuard(head);
    let mut builders = HashMap::<Vec<u8>, InterfaceBuilder>::new();
    let mut current = guard.0;

    while !current.is_null() {
        // SAFETY: every node belongs to the live getifaddrs list held by guard.
        // Null name/address pointers are checked before dereference.
        unsafe {
            let entry = &*current;
            if !entry.ifa_name.is_null() {
                let name = CStr::from_ptr(entry.ifa_name).to_bytes();
                let builder = builders.entry(name.to_vec()).or_default();
                builder.flags |= entry.ifa_flags;
                if !entry.ifa_addr.is_null()
                    && i32::from((*entry.ifa_addr).sa_family) == libc::AF_PACKET
                {
                    let link = entry.ifa_addr.cast::<libc::sockaddr_ll>();
                    builder.hardware_type = (*link).sll_hatype;
                    if (*link).sll_halen == 6 {
                        let mut octets = [0; 6];
                        octets.copy_from_slice(&(&(*link).sll_addr)[..6]);
                        builder.mac_address = Some(MacAddress::new(octets));
                    }
                }
            }
            current = entry.ifa_next;
        }
    }

    let mut interfaces = builders
        .into_iter()
        .map(|(name, builder)| {
            let is_loopback = builder.flags & interface_flag(libc::IFF_LOOPBACK) != 0
                || builder.hardware_type == libc::ARPHRD_LOOPBACK;
            let is_point_to_point = builder.flags & interface_flag(libc::IFF_POINTOPOINT) != 0;
            let is_up = builder.flags & interface_flag(libc::IFF_UP) != 0
                && builder.flags & interface_flag(libc::IFF_RUNNING) != 0;
            let nature = classify_device_nature(
                is_loopback,
                is_point_to_point,
                builder.hardware_type == libc::ARPHRD_ETHER,
                || interface_is_wireless(&name),
                || interface_is_physical(&name),
            );

            normalize(DeviceSnapshot {
                mac_address: builder.mac_address,
                name: encode_interface_name(&name),
                nature,
                is_up,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    interfaces.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(interfaces)
}

const fn interface_flag(flag: libc::c_int) -> u32 {
    flag.unsigned_abs()
}

fn classify_device_nature<W, P>(
    is_loopback: bool,
    is_point_to_point: bool,
    is_ethernet_hardware: bool,
    wireless_probe: W,
    physical_probe: P,
) -> DeviceNature
where
    W: FnOnce() -> io::Result<bool>,
    P: FnOnce() -> io::Result<bool>,
{
    if is_loopback {
        DeviceNature::Loopback
    } else if is_point_to_point {
        DeviceNature::PointToPoint
    } else {
        match wireless_probe() {
            Ok(true) => DeviceNature::Wireless,
            Ok(false) => match physical_probe() {
                Ok(true) if is_ethernet_hardware => DeviceNature::PhysicalEthernet,
                _ => DeviceNature::VirtualOrUnknown,
            },
            _ => DeviceNature::VirtualOrUnknown,
        }
    }
}

fn interface_is_wireless(name: &[u8]) -> io::Result<bool> {
    if interface_name_looks_wireless(name) {
        return Ok(true);
    }
    let interface_path = interface_sysfs_path(name);
    Ok(interface_path.join("wireless").try_exists()?
        || interface_path.join("phy80211").try_exists()?)
}

fn interface_name_looks_wireless(name: &[u8]) -> bool {
    const GENERIC_PREFIXES: &[&[u8]] = &[b"wlan", b"wlp", b"wlx"];
    const MEDIATEK_PREFIXES: &[&[u8]] = &[b"ra", b"rai", b"wds", b"wdsi", b"apcli", b"apclii"];

    if GENERIC_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return true;
    }
    MEDIATEK_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(*prefix)
            .and_then(|suffix| suffix.first())
            .is_some_and(u8::is_ascii_digit)
    })
}

fn interface_is_physical(name: &[u8]) -> io::Result<bool> {
    let interface_path = interface_sysfs_path(name);
    let uevent = fs::read_to_string(interface_path.join("uevent"))?;
    let iflink = read_sysfs_u32(&interface_path.join("iflink"))?;
    let ifindex = read_sysfs_u32(&interface_path.join("ifindex"))?;
    Ok(interface_uevent_is_physical(&uevent, iflink, ifindex))
}

fn interface_uevent_is_physical(uevent: &str, iflink: u32, ifindex: u32) -> bool {
    let device_type = uevent
        .lines()
        .find_map(|line| line.strip_prefix("DEVTYPE="));
    (device_type.is_none() || device_type == Some("ethernet")) && iflink == ifindex
}

fn read_sysfs_u32(path: &Path) -> io::Result<u32> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_error| io::Error::new(io::ErrorKind::InvalidData, "invalid sysfs integer"))
}

fn interface_sysfs_path(name: &[u8]) -> std::path::PathBuf {
    Path::new("/sys/class/net").join(OsString::from_vec(name.to_vec()))
}

fn encode_interface_name(name: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(name.len());
    for &byte in name {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn decode_interface_name(name: &str) -> Result<Vec<u8>> {
    let bytes = name.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let Some((&high, rest)) = bytes.get(cursor + 1..).and_then(|tail| tail.split_first())
            else {
                return Err(PlatformError::InvalidInterfaceId);
            };
            let Some((&low, _)) = rest.split_first() else {
                return Err(PlatformError::InvalidInterfaceId);
            };
            let Some(high) = hex_value(high) else {
                return Err(PlatformError::InvalidInterfaceId);
            };
            let Some(low) = hex_value(low) else {
                return Err(PlatformError::InvalidInterfaceId);
            };
            decoded.push((high << 4) | low);
            cursor += 3;
        } else {
            decoded.push(bytes[cursor]);
            cursor += 1;
        }
    }
    Ok(decoded)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn create_packet_socket(interface: &str) -> Result<OwnedFd> {
    // SAFETY: socket arguments are constants; the returned fd is immediately
    // wrapped in an owning descriptor on success.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(libc::htons(ETH_P_ALL)),
        )
    };
    if descriptor < 0 {
        return Err(map_native_io_error(
            "create AF_PACKET socket",
            interface,
            &io::Error::last_os_error(),
        ));
    }
    // SAFETY: `descriptor` is newly owned and has not been transferred elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn bind_packet_socket(socket: libc::c_int, interface: &str, ifindex: i32) -> Result<()> {
    let address = packet_address(ifindex)?;

    // SAFETY: `address` is fully initialized for the selected address length.
    let result = unsafe {
        libc::bind(
            socket,
            (&raw const address).cast(),
            socket_address_length::<libc::sockaddr_ll>("bind AF_PACKET socket")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "bind AF_PACKET socket",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn packet_address(ifindex: i32) -> Result<libc::sockaddr_ll> {
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family =
        u16::try_from(libc::AF_PACKET).map_err(|_error| PlatformError::OperationFailed {
            operation: "construct AF_PACKET address",
            message: "AF_PACKET address family is invalid".to_owned(),
        })?;
    address.sll_protocol = libc::htons(ETH_P_ALL);
    address.sll_ifindex = ifindex;
    Ok(address)
}

fn set_receive_timeout(socket: libc::c_int, interface: &str, timeout: Duration) -> Result<()> {
    let value = timeout_to_timeval(timeout)?;

    // SAFETY: `value` is a correctly sized timeval for SO_RCVTIMEO.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const value).cast(),
            socket_address_length::<libc::timeval>("configure receive timeout")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "configure receive timeout",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

#[expect(
    clippy::unnecessary_fallible_conversions,
    reason = "libc time and ancillary-length field widths vary by target"
)]
fn timeout_to_timeval(timeout: Duration) -> Result<libc::timeval> {
    if timeout.is_zero() {
        return Err(PlatformError::InvalidReadTimeout {
            actual: timeout,
            minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
            maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
        });
    }

    let mut seconds = timeout.as_secs();
    let mut microseconds = timeout.subsec_micros();
    if !timeout.subsec_nanos().is_multiple_of(1_000) {
        microseconds = microseconds.saturating_add(1);
        if microseconds == 1_000_000 {
            seconds = seconds.saturating_add(1);
            microseconds = 0;
        }
    }

    let seconds = seconds
        .try_into()
        .map_err(|_error| PlatformError::InvalidReadTimeout {
            actual: timeout,
            minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
            maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
        })?;
    let microseconds =
        microseconds
            .try_into()
            .map_err(|_error| PlatformError::InvalidReadTimeout {
                actual: timeout,
                minimum: FrameChannelConfig::MIN_READ_TIMEOUT,
                maximum: FrameChannelConfig::MAX_READ_TIMEOUT,
            })?;
    Ok(libc::timeval {
        tv_sec: seconds,
        tv_usec: microseconds,
    })
}

fn attach_eapol_filter(socket: libc::c_int, interface: &str, snapshot_length: usize) -> Result<()> {
    let snapshot_length =
        u32::try_from(snapshot_length).map_err(|_error| PlatformError::InvalidSnapshotLength {
            actual: snapshot_length,
            minimum: FrameChannelConfig::MIN_SNAPSHOT_LENGTH,
            maximum: FrameChannelConfig::MAX_SNAPSHOT_LENGTH,
        })?;
    let mut program = eapol_filter_program(snapshot_length);
    let mut filter = libc::sock_fprog {
        len: u16::try_from(program.len()).map_err(|_error| PlatformError::OperationFailed {
            operation: "install EAPOL filter",
            message: "BPF program length exceeds sock_fprog range".to_owned(),
        })?,
        filter: program.as_mut_ptr(),
    };

    // SAFETY: `filter` points to a live instruction vector for this call.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw mut filter).cast(),
            socket_address_length::<libc::sock_fprog>("install EAPOL filter")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "install EAPOL filter",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn enable_packet_auxdata(socket: libc::c_int, interface: &str) -> Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: `enabled` is a valid int for PACKET_AUXDATA.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_PACKET,
            libc::PACKET_AUXDATA,
            (&raw const enabled).cast(),
            socket_address_length::<libc::c_int>("enable packet auxiliary data")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "enable packet auxiliary data",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn enable_promiscuous(socket: libc::c_int, interface: &str, ifindex: i32) -> Result<()> {
    let membership = libc::packet_mreq {
        mr_ifindex: ifindex,
        mr_type: u16::try_from(libc::PACKET_MR_PROMISC).map_err(|_error| {
            PlatformError::OperationFailed {
                operation: "enable promiscuous capture",
                message: "promiscuous membership type exceeds packet_mreq range".to_owned(),
            }
        })?,
        mr_alen: 0,
        mr_address: [0; 8],
    };

    // SAFETY: `membership` is fully initialized and the kernel interprets it as
    // PACKET_ADD_MEMBERSHIP for the lifetime of this call.
    let result = unsafe {
        libc::setsockopt(
            socket,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            (&raw const membership).cast(),
            socket_address_length::<libc::packet_mreq>("enable promiscuous capture")?,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(map_native_io_error(
            "enable promiscuous capture",
            interface,
            &io::Error::last_os_error(),
        ))
    }
}

fn vlan_metadata(message: &libc::msghdr) -> Option<libc::tpacket_auxdata> {
    // SAFETY: ancillary pointers are supplied by recvmsg and bounded by
    // msg_controllen. The auxiliary payload is read without creating a reference
    // with stronger alignment requirements than the socket buffer provides.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_PACKET
                && (*header).cmsg_type == libc::PACKET_AUXDATA
            {
                return Some(ptr::read_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::tpacket_auxdata>(),
                ));
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
        None
    }
}

fn restore_vlan_tag(
    frame: &mut Vec<u8>,
    auxdata: &libc::tpacket_auxdata,
    maximum_length: usize,
) -> Result<()> {
    if auxdata.tp_status & libc::TP_STATUS_VLAN_VALID == 0 {
        return Ok(());
    }
    let restored_length = frame
        .len()
        .checked_add(4)
        .filter(|length| *length <= maximum_length)
        .ok_or_else(|| PlatformError::OperationFailed {
            operation: "restore VLAN tag",
            message: "received frame exceeds snapshot length after VLAN restoration".to_owned(),
        })?;
    if frame.len() < 12 {
        return Err(PlatformError::OperationFailed {
            operation: "restore VLAN tag",
            message: "received frame is too short to contain an Ethernet header".to_owned(),
        });
    }

    let tpid = if auxdata.tp_status & libc::TP_STATUS_VLAN_TPID_VALID != 0 {
        auxdata.tp_vlan_tpid
    } else {
        VLAN_TPID_8021Q_WIRE
    };
    let mut restored = Vec::with_capacity(restored_length);
    restored.extend_from_slice(&frame[..12]);
    restored.extend_from_slice(&tpid.to_be_bytes());
    restored.extend_from_slice(&auxdata.tp_vlan_tci.to_be_bytes());
    restored.extend_from_slice(&frame[12..]);
    *frame = restored;
    Ok(())
}

fn socket_address_length<T>(operation: &'static str) -> Result<libc::socklen_t> {
    libc::socklen_t::try_from(size_of::<T>()).map_err(|_error| PlatformError::OperationFailed {
        operation,
        message: "socket structure length exceeds platform range".to_owned(),
    })
}

fn map_native_io_error(
    operation: &'static str,
    interface: &str,
    error: &io::Error,
) -> PlatformError {
    if matches!(
        error.raw_os_error(),
        Some(libc::ENODEV | libc::ENXIO | libc::ENETDOWN)
    ) {
        PlatformError::InterfaceUnavailable {
            interface: interface.to_owned(),
        }
    } else {
        map_io_error(operation, interface, error)
    }
}

fn eapol_filter_program(snapshot_length: u32) -> Vec<sock_filter> {
    vec![
        instruction(LOAD_ETHERTYPE, 0, 0, 12),
        instruction(COMPARE_IMMEDIATE, 11, 0, EAPOL_ETHERTYPE),
        instruction(COMPARE_IMMEDIATE, 2, 0, VLAN_TPID_8021Q),
        instruction(COMPARE_IMMEDIATE, 1, 0, VLAN_TPID_8021AD),
        instruction(RETURN_IMMEDIATE, 0, 0, 0),
        instruction(LOAD_ETHERTYPE, 0, 0, 16),
        instruction(COMPARE_IMMEDIATE, 6, 0, EAPOL_ETHERTYPE),
        instruction(COMPARE_IMMEDIATE, 2, 0, VLAN_TPID_8021Q),
        instruction(COMPARE_IMMEDIATE, 1, 0, VLAN_TPID_8021AD),
        instruction(RETURN_IMMEDIATE, 0, 0, 0),
        instruction(LOAD_ETHERTYPE, 0, 0, 20),
        instruction(COMPARE_IMMEDIATE, 1, 0, EAPOL_ETHERTYPE),
        instruction(RETURN_IMMEDIATE, 0, 0, 0),
        instruction(RETURN_IMMEDIATE, 0, 0, snapshot_length),
    ]
}

const fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "classic BPF opcode constants fit in sock_filter::code"
)]
const fn bpf_opcode(code: u32) -> u16 {
    code as u16
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer was returned by one successful getifaddrs
            // call and this guard is its sole owner.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_with_ether_type_at(offset: usize, ether_type: u16) -> Vec<u8> {
        let mut frame = vec![0; offset + 2];
        frame[offset..offset + 2].copy_from_slice(&ether_type.to_be_bytes());
        frame
    }

    fn run_filter(program: &[sock_filter], frame: &[u8]) -> bool {
        let mut pc = 0;
        let mut accumulator = 0_u32;
        for _ in 0..program.len() {
            let instruction = program[pc];
            match instruction.code {
                LOAD_ETHERTYPE => {
                    let Ok(offset) = usize::try_from(instruction.k) else {
                        return false;
                    };
                    accumulator = frame.get(offset..offset + 2).map_or(0, |bytes| {
                        u32::from(u16::from_be_bytes([bytes[0], bytes[1]]))
                    });
                    pc += 1;
                }
                COMPARE_IMMEDIATE => {
                    pc += if accumulator == instruction.k {
                        1 + usize::from(instruction.jt)
                    } else {
                        1 + usize::from(instruction.jf)
                    };
                }
                RETURN_IMMEDIATE => return instruction.k != 0,
                _ => return false,
            }
        }
        false
    }

    #[test]
    fn eapol_filter_accepts_untagged_and_vlan_tagged_frames() {
        let program = eapol_filter_program(4096);
        let untagged = frame_with_ether_type_at(12, EAPOL_ETHERTYPE_WIRE);
        let mut single_vlan = frame_with_ether_type_at(16, EAPOL_ETHERTYPE_WIRE);
        single_vlan[12..14].copy_from_slice(&VLAN_TPID_8021Q_WIRE.to_be_bytes());
        let mut double_vlan = frame_with_ether_type_at(20, EAPOL_ETHERTYPE_WIRE);
        double_vlan[12..14].copy_from_slice(&VLAN_TPID_8021AD_WIRE.to_be_bytes());
        double_vlan[16..18].copy_from_slice(&VLAN_TPID_8021Q_WIRE.to_be_bytes());

        assert!(run_filter(&program, &untagged));
        assert!(run_filter(&program, &single_vlan));
        assert!(run_filter(&program, &double_vlan));
    }

    #[test]
    fn eapol_filter_rejects_non_eapol_and_unsupported_encapsulation() {
        let program = eapol_filter_program(4096);
        let ipv4 = frame_with_ether_type_at(12, 0x0800);
        let non_eapol_in_vlan = frame_with_ether_type_at(16, 0x0800);

        assert!(!run_filter(&program, &ipv4));
        assert!(!run_filter(&program, &non_eapol_in_vlan));
    }

    #[test]
    fn native_enumeration_returns_unique_nonempty_ids() -> Result<()> {
        let interfaces = LinuxEthernet.interfaces()?;
        assert!(!interfaces.is_empty());

        let mut ids = std::collections::HashSet::new();
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
    fn opening_loopback_is_rejected_before_socket_activation() -> Result<()> {
        let interfaces = LinuxEthernet.interfaces()?;
        let loopback = interfaces
            .iter()
            .find(|interface| interface.kind == InterfaceKind::Loopback)
            .ok_or_else(|| PlatformError::OperationFailed {
                operation: "test loopback lookup",
                message: "no loopback interface found".to_owned(),
            })?;

        assert!(matches!(
            LinuxEthernet.open(&loopback.id, &FrameChannelConfig::default()),
            Err(PlatformError::UnsupportedCapability {
                capability: "non-physical Ethernet wired interface",
            })
        ));
        Ok(())
    }

    #[test]
    fn outbound_frame_length_uses_the_shared_ethernet_boundary() {
        assert_eq!(
            validate_outbound_frame_length(MIN_ETHERNET_FRAME_LENGTH - 1),
            Err(PlatformError::InvalidFrameLength {
                actual: MIN_ETHERNET_FRAME_LENGTH - 1,
                minimum: MIN_ETHERNET_FRAME_LENGTH,
                maximum: MAX_ETHERNET_FRAME_LENGTH,
            })
        );
        assert!(validate_outbound_frame_length(MIN_ETHERNET_FRAME_LENGTH).is_ok());
        assert!(validate_outbound_frame_length(MAX_ETHERNET_FRAME_LENGTH).is_ok());
        assert!(validate_outbound_frame_length(MAX_ETHERNET_FRAME_LENGTH + 1).is_err());
    }

    #[test]
    #[ignore = "requires CAP_NET_RAW and activates a real AF_PACKET socket"]
    fn packet_socket_completes_a_bounded_send_and_receive_timeout() -> Result<()> {
        let interface = "lo";
        let interface_c =
            CString::new(interface).map_err(|_error| PlatformError::OperationFailed {
                operation: "test interface name",
                message: "loopback interface name contains NUL".to_owned(),
            })?;
        // SAFETY: `interface_c` is a valid NUL-terminated interface name.
        let raw_ifindex = unsafe { libc::if_nametoindex(interface_c.as_ptr()) };
        let ifindex =
            i32::try_from(raw_ifindex).map_err(|_error| PlatformError::InterfaceUnavailable {
                interface: interface.to_owned(),
            })?;
        let socket = create_packet_socket(interface)?;
        bind_packet_socket(socket.as_raw_fd(), interface, ifindex)?;
        enable_packet_auxdata(socket.as_raw_fd(), interface)?;
        let timeout = Duration::from_millis(100);
        set_receive_timeout(socket.as_raw_fd(), interface, timeout)?;
        attach_eapol_filter(socket.as_raw_fd(), interface, 4096)?;
        let mut channel = LinuxFrameChannel {
            socket,
            interface: interface.to_owned(),
            ifindex,
            local_mac: MacAddress::new([2, 3, 4, 5, 6, 7]),
            snapshot_length: 4096,
            read_timeout: timeout,
        };
        let mut frame = vec![0; 60];
        frame[0..6].copy_from_slice(&MacAddress::PAE_GROUP.octets());
        frame[6..12].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
        frame[12..14].copy_from_slice(&EAPOL_ETHERTYPE_WIRE.to_be_bytes());

        channel.send(&frame)?;
        assert_eq!(channel.receive()?, ReceiveOutcome::Timeout);
        Ok(())
    }

    #[test]
    fn timeout_rounding_never_creates_a_zero_timeval() -> Result<()> {
        let sub_microsecond = timeout_to_timeval(Duration::from_nanos(1))?;
        assert_eq!(sub_microsecond.tv_sec, 0);
        assert_eq!(sub_microsecond.tv_usec, 1);

        let exact = timeout_to_timeval(Duration::from_millis(250))?;
        assert_eq!(exact.tv_sec, 0);
        assert_eq!(exact.tv_usec, 250_000);
        Ok(())
    }

    #[test]
    fn classification_failure_degrades_to_virtual_or_unknown() {
        let probe_error = || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "classification denied",
            ))
        };

        assert_eq!(
            classify_device_nature(false, false, true, probe_error, || Ok(true)),
            DeviceNature::VirtualOrUnknown
        );
        assert_eq!(
            classify_device_nature(false, false, true, || Ok(false), probe_error),
            DeviceNature::VirtualOrUnknown
        );
        assert_eq!(
            classify_device_nature(false, false, true, || Ok(false), || Ok(true)),
            DeviceNature::PhysicalEthernet
        );
        assert_eq!(
            classify_device_nature(false, false, true, || Ok(true), probe_error),
            DeviceNature::Wireless
        );
        assert_eq!(
            classify_device_nature(true, false, false, probe_error, probe_error),
            DeviceNature::Loopback
        );
    }

    #[test]
    fn physical_classification_accepts_driver_backed_ethernet_and_rejects_virtual_types() {
        assert!(interface_uevent_is_physical(
            "INTERFACE=eth3\nIFINDEX=2\n",
            2,
            2
        ));
        assert!(!interface_uevent_is_physical(
            "DEVTYPE=bridge\nINTERFACE=br0\nIFINDEX=13\n",
            13,
            13
        ));
        assert!(!interface_uevent_is_physical(
            "INTERFACE=veth0\nIFINDEX=5\n",
            5,
            3
        ));
    }

    #[test]
    fn padavan_wireless_names_are_not_physical_ethernet() {
        for name in [
            b"rai0".as_slice(),
            b"rai1",
            b"ra0",
            b"wds0",
            b"wdsi0",
            b"apcli0",
            b"apclii0",
            b"wlan0",
        ] {
            assert!(interface_name_looks_wireless(name));
        }
        assert!(!interface_name_looks_wireless(b"eth2"));
        assert!(!interface_name_looks_wireless(b"eth3"));
        assert!(!interface_name_looks_wireless(b"br0"));
    }

    #[test]
    fn interface_ids_round_trip_non_utf8_names() -> Result<()> {
        let raw_name = b"eth\xff";
        let encoded = encode_interface_name(raw_name);

        assert_eq!(encoded, "eth%FF");
        assert_eq!(decode_interface_name(&encoded)?, raw_name);
        assert_eq!(
            decode_interface_name("eth%"),
            Err(PlatformError::InvalidInterfaceId)
        );
        Ok(())
    }

    #[test]
    fn vlan_auxdata_restores_the_stripped_tag() -> Result<()> {
        let mut frame = frame_with_ether_type_at(12, EAPOL_ETHERTYPE_WIRE);
        let auxdata = libc::tpacket_auxdata {
            tp_status: libc::TP_STATUS_VLAN_VALID | libc::TP_STATUS_VLAN_TPID_VALID,
            tp_len: 0,
            tp_snaplen: 0,
            tp_mac: 0,
            tp_net: 0,
            tp_vlan_tci: 0x2001,
            tp_vlan_tpid: 0x88a8,
        };

        restore_vlan_tag(&mut frame, &auxdata, 4096)?;

        assert_eq!(&frame[12..16], &[0x88, 0xa8, 0x20, 0x01]);
        assert_eq!(&frame[16..18], &EAPOL_ETHERTYPE_WIRE.to_be_bytes());
        Ok(())
    }
}
