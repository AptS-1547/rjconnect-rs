//! Bounded codecs for the two private-attribute encodings recovered from the
//! legacy Ruijie client.
//!
//! Wireless PEAP data uses a compact `kind + length + value` stream. Wired
//! Ethernet responses append RADIUS Vendor-Specific Attributes containing the
//! Ruijie enterprise identifier `0x00001311`. These formats look similar but
//! have different length semantics and therefore intentionally use separate
//! types.

#![forbid(unsafe_code)]

mod compact;
mod kind;
mod radius;
mod wired;

pub use compact::{
    CompactAttribute, CompactAttributeError, CompactAttributeReader, CompactAttributeWriter,
};
pub use kind::AttributeKind;
pub use radius::{
    RADIUS_VENDOR_SPECIFIC_TYPE, RUIJIE_VENDOR_ID, RadiusAttribute, RadiusAttributeError,
    RadiusAttributeReader, RadiusAttributeWriter,
};
pub use wired::{
    WIRED_PREAMBLE_LENGTH, WiredPreamble, WiredVendorTrailer, WiredVendorTrailerError,
    WiredVendorTrailerWriter,
};

/// Maximum complete private-attribute block accepted by the recovered client.
pub const MAX_VENDOR_PAYLOAD_LENGTH: usize = 1400;
