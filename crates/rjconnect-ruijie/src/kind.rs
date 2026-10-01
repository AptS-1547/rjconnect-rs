/// A Ruijie private attribute type byte.
///
/// Unknown numeric values are preserved by [`Self::new`] rather than rejected,
/// allowing packet captures from newer authenticators to remain diagnosable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttributeKind(u8);

impl AttributeKind {
    /// Password response used by the wired private method.
    pub const PASSWORD: Self = Self(0x2f);
    /// V3 verification block used by legacy wired authentication.
    pub const V3_HASH: Self = Self(0x4d);
    /// Reauthentication interval supplied by the server.
    pub const REAUTH_INTERVAL: Self = Self(0x56);
    /// Hello interval supplied by the server.
    pub const HELLO_INTERVAL: Self = Self(0x59);
    /// Direct-communication server port.
    pub const SERVER_PORT: Self = Self(0x5a);
    /// Direct-communication server IPv4 address.
    pub const SERVER_IPV4: Self = Self(0x5b);
    /// Legacy direct-communication key material.
    pub const SESSION_KEY: Self = Self(0x5c);
    /// Legacy direct-communication initialization vector.
    pub const SESSION_IV: Self = Self(0x5d);
    /// Server UTC time.
    pub const SERVER_TIME: Self = Self(0x5e);
    /// Password response used inside the recovered PEAP flow.
    pub const PEAP_PASSWORD: Self = Self(0x5f);
    /// V3 verification block used by PEAP.
    pub const PEAP_V3_HASH: Self = Self(0x60);
    /// RADIUS server capability type.
    pub const RADIUS_TYPE: Self = Self(0x61);
    /// Server switch result.
    pub const SERVER_SWITCH_RESULT: Self = Self(0x65);
    /// Server-provided service list.
    pub const SERVICE_LIST: Self = Self(0x66);
    /// User login URL.
    pub const USER_LOGIN_URL: Self = Self(0x68);
    /// Direct-communication client port.
    pub const CLIENT_PORT: Self = Self(0x6e);
    /// Client release version.
    pub const RELEASE_VERSION: Self = Self(0x6f);
    /// Client operating-system bitness.
    pub const OS_BITS: Self = Self(0x70);
    /// uTrust URL.
    pub const UTRUST_URL: Self = Self(0x72);
    /// Proxy-detection policy bits.
    pub const PROXY_POLICY: Self = Self(0x74);
    /// uTrust display policy.
    pub const UTRUST_DISPLAY: Self = Self(0x77);
    /// Highest direct-communication version supported by the peer.
    pub const DIRECT_COMMUNICATION_VERSION: Self = Self(0x79);
    /// Direct-communication heartbeat flags.
    pub const DIRECT_COMMUNICATION_HEARTBEAT: Self = Self(0x80);

    /// Creates a kind from its wire value.
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns the wire value.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }
}
