//! Linux wired Ethernet platform adapter.
//!
//! The native implementation uses `AF_PACKET` for bounded EAPOL capture and
//! transmission. Portable interface normalization remains testable on every
//! host; native symbols are exported only when targeting Linux.

#![deny(unsafe_code)]

#[cfg(any(target_os = "linux", test))]
mod error;

#[cfg(any(target_os = "linux", test))]
mod normalize;

#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "AF_PACKET socket and syscall boundaries require audited libc FFI"
)]
mod native;

#[cfg(target_os = "linux")]
pub use native::{LinuxEthernet, LinuxFrameChannel};
