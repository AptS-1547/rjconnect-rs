//! Pure authentication state machine for wired EAPOL authentication.
//!
//! The machine owns no sockets, timers, or platform handles. It accepts typed
//! events and returns effects for a runtime to execute.

#![forbid(unsafe_code)]

mod credentials;
mod machine;
mod md5_response;

pub use credentials::{CredentialError, Credentials};
pub use machine::{
    AuthEffect, AuthError, AuthEvent, AuthMachine, AuthState, FailureReason, IncomingEap,
    Md5Challenge, RequestContext, SessionPolicy, TimerKind,
};
