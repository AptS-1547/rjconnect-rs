//! macOS Ethernet platform backend.
//!
//! The native implementation uses libpcap/BPF for bounded EAPOL capture and
//! transmission. Portable normalization helpers remain testable on every CI
//! host; native symbols are exported only when targeting macOS.

#![deny(unsafe_code)]

#[cfg(any(target_os = "macos", test))]
mod normalize;

#[cfg(target_os = "macos")]
mod native;

#[cfg(target_os = "macos")]
pub use native::{MacosEthernet, MacosFrameChannel};
