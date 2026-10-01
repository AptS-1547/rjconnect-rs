use std::{fmt, time::Duration};

use rjconnect_eapol::{EapCode, EapMethod, EapPacket};
use thiserror::Error;

use crate::{Credentials, md5_response};

/// Timer owned by the authentication runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerKind {
    /// Waiting for the first authenticator request.
    Start,
    /// Waiting for an authentication method result.
    Authentication,
    /// Backoff after failure or timeout.
    Held,
}

/// Stable authentication state exposed to applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// No session has started.
    Idle,
    /// EAPOL-Start was emitted and the peer is awaiting an EAP request.
    AwaitingRequest,
    /// At least one method response has been emitted.
    Authenticating,
    /// EAP-Success was received.
    Authenticated,
    /// The session is waiting before a retry.
    Held,
    /// The session has ended and will emit no further protocol effects.
    Terminated,
}

/// Policy controlling timers and retry limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    start_timeout: Duration,
    authentication_timeout: Duration,
    held_duration: Duration,
    maximum_attempts: u8,
}

impl SessionPolicy {
    /// Creates a validated session policy.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidPolicy`] if a duration or retry count is
    /// zero.
    pub const fn new(
        start_timeout: Duration,
        authentication_timeout: Duration,
        held_duration: Duration,
        maximum_attempts: u8,
    ) -> Result<Self, AuthError> {
        if start_timeout.is_zero()
            || authentication_timeout.is_zero()
            || held_duration.is_zero()
            || maximum_attempts == 0
        {
            return Err(AuthError::InvalidPolicy);
        }
        Ok(Self {
            start_timeout,
            authentication_timeout,
            held_duration,
            maximum_attempts,
        })
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            start_timeout: Duration::from_secs(3),
            authentication_timeout: Duration::from_secs(45),
            held_duration: Duration::from_secs(3),
            maximum_attempts: 3,
        }
    }
}

/// Owned EAP input accepted by the state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingEap {
    /// Packet code.
    pub code: EapCode,
    /// Packet identifier.
    pub identifier: u8,
    /// Optional method for request/response packets.
    pub method: Option<EapMethod>,
    /// Method payload.
    pub payload: Vec<u8>,
}

/// Validated 16-byte challenge from an EAP-MD5 request.
///
/// The bytes are needed by the standard MD5 response and by recovered Ruijie
/// verification attributes. `Debug` intentionally redacts the value so an
/// effect can be traced without copying a live challenge into logs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Md5Challenge([u8; md5_response::MD5_CHALLENGE_LENGTH]);

impl Md5Challenge {
    /// Returns the challenge bytes for protocol encoders.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; md5_response::MD5_CHALLENGE_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for Md5Challenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Md5Challenge(<redacted>)")
    }
}

/// Semantic reason for an outbound EAP response.
///
/// A wired session uses this context to build the correct Ruijie trailer
/// without reparsing the response bytes or reaching into state-machine state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestContext {
    /// Response to Request/Identity.
    Identity,
    /// Response to Request/MD5-Challenge.
    Md5Challenge {
        /// Validated challenge used by the response.
        challenge: Md5Challenge,
    },
    /// Response to the recovered Ruijie private method.
    RuijiePrivate,
    /// Acknowledgement of Request/Notification.
    Notification,
    /// Legacy NAK for a method not supported by this session.
    Nak {
        /// Method requested by the authenticator.
        requested: EapMethod,
    },
}

impl IncomingEap {
    /// Copies a validated borrowed EAP packet into an owned event.
    #[must_use]
    pub fn from_packet(packet: &EapPacket<'_>) -> Self {
        Self {
            code: packet.code,
            identifier: packet.identifier,
            method: packet.method,
            payload: packet.payload.to_vec(),
        }
    }
}

/// Event delivered to the pure authentication machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthEvent {
    /// Start a new session.
    Start,
    /// Validated EAP packet received from the authenticator.
    Eap(IncomingEap),
    /// Runtime timer expired.
    TimerExpired(TimerKind),
    /// User or host requested a graceful stop.
    Stop,
}

/// Stable failure category for application and retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// Authenticator sent EAP-Failure.
    Rejected,
    /// No request arrived after EAPOL-Start.
    StartTimeout,
    /// Authentication did not complete before the method timeout.
    AuthenticationTimeout,
    /// Retry budget was exhausted.
    RetryExhausted,
}

/// Side effect returned for execution by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthEffect {
    /// Send an EAPOL-Start packet.
    SendStart,
    /// Send an encoded EAP packet inside EAPOL.
    SendEap {
        /// Complete encoded EAP packet.
        packet: Vec<u8>,
        /// Semantic request context for vendor-trailer construction.
        context: RequestContext,
    },
    /// Send an EAPOL-Logoff packet.
    SendLogoff,
    /// Arm or replace a runtime timer.
    ArmTimer {
        /// Timer identity.
        kind: TimerKind,
        /// Timer duration.
        duration: Duration,
    },
    /// Cancel a runtime timer if it exists.
    CancelTimer(TimerKind),
    /// Notify the application that the controlled port may proceed.
    Authenticated,
    /// Notify the application of a failed attempt.
    Failed {
        /// Failure category.
        reason: FailureReason,
        /// Whether the machine will retry after its held timer.
        will_retry: bool,
    },
    /// Notify the application that the session ended.
    Terminated {
        /// Optional terminal failure category.
        reason: Option<FailureReason>,
    },
}

/// Error returned for malformed method payloads or invalid runtime events.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Policy contains a zero duration or zero retry count.
    #[error("session policy values must be non-zero")]
    InvalidPolicy,
    /// An event is not valid in the current terminal or idle state.
    #[error("event {event} is invalid while authentication state is {state:?}")]
    InvalidEvent {
        /// Stable event label.
        event: &'static str,
        /// State in which the event was rejected.
        state: AuthState,
    },
    /// EAP request/response omitted a method.
    #[error("EAP request is missing its method")]
    MissingMethod,
    /// EAP-MD5 value-size or challenge length is invalid.
    #[error("EAP-MD5 challenge must contain exactly 16 bytes, got {actual}")]
    InvalidMd5ChallengeLength {
        /// Actual challenge byte count.
        actual: usize,
    },
    /// Success or failure did not match the most recent request identifier.
    #[error("EAP result identifier mismatch: expected {expected}, got {actual}")]
    UnexpectedIdentifier {
        /// Most recent request identifier.
        expected: u8,
        /// Identifier carried by Success or Failure.
        actual: u8,
    },
    /// Failed to encode a response packet.
    #[error("failed to encode EAP response: {0}")]
    Codec(String),
    /// Validated credentials violated an internal wire-length invariant.
    #[error("validated credential length cannot be represented on the wire")]
    CredentialLengthInvariant,
}

/// Deterministic authentication state machine.
#[derive(Debug)]
pub struct AuthMachine {
    credentials: Credentials,
    policy: SessionPolicy,
    state: AuthState,
    attempts: u8,
    last_identifier: Option<u8>,
}

impl AuthMachine {
    /// Creates an idle machine with validated credentials and policy.
    #[must_use]
    pub const fn new(credentials: Credentials, policy: SessionPolicy) -> Self {
        Self {
            credentials,
            policy,
            state: AuthState::Idle,
            attempts: 0,
            last_identifier: None,
        }
    }

    /// Returns the current stable state.
    #[must_use]
    pub const fn state(&self) -> AuthState {
        self.state
    }

    /// Processes one event atomically and returns effects for the runtime.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid event ordering, malformed EAP method
    /// payloads, or response encoding failure. State is not advanced when
    /// method validation fails.
    pub fn handle(&mut self, event: AuthEvent) -> Result<Vec<AuthEffect>, AuthError> {
        match event {
            AuthEvent::Start => self.start(),
            AuthEvent::Eap(packet) => self.handle_eap(&packet),
            AuthEvent::TimerExpired(kind) => self.handle_timer(kind),
            AuthEvent::Stop => Ok(self.stop()),
        }
    }

    fn start(&mut self) -> Result<Vec<AuthEffect>, AuthError> {
        if self.state != AuthState::Idle {
            return Err(AuthError::InvalidEvent {
                event: "start",
                state: self.state,
            });
        }
        self.attempts = 1;
        self.last_identifier = None;
        self.state = AuthState::AwaitingRequest;
        Ok(self.start_effects())
    }

    fn handle_eap(&mut self, packet: &IncomingEap) -> Result<Vec<AuthEffect>, AuthError> {
        if matches!(
            self.state,
            AuthState::Idle | AuthState::Held | AuthState::Terminated
        ) {
            return Err(AuthError::InvalidEvent {
                event: "EAP packet",
                state: self.state,
            });
        }

        match packet.code {
            EapCode::Request => self.handle_request(packet),
            EapCode::Success => {
                self.validate_result_identifier(packet.identifier)?;
                self.last_identifier = Some(packet.identifier);
                self.state = AuthState::Authenticated;
                Ok(vec![
                    AuthEffect::CancelTimer(TimerKind::Start),
                    AuthEffect::CancelTimer(TimerKind::Authentication),
                    AuthEffect::Authenticated,
                ])
            }
            EapCode::Failure => {
                self.validate_result_identifier(packet.identifier)?;
                Ok(self.enter_held(FailureReason::Rejected))
            }
            EapCode::Response | EapCode::Unknown(_) => Ok(Vec::new()),
        }
    }

    const fn validate_result_identifier(&self, actual: u8) -> Result<(), AuthError> {
        let Some(expected) = self.last_identifier else {
            return Err(AuthError::InvalidEvent {
                event: "EAP result before request",
                state: self.state,
            });
        };
        if actual != expected {
            return Err(AuthError::UnexpectedIdentifier { expected, actual });
        }
        Ok(())
    }

    fn handle_request(&mut self, packet: &IncomingEap) -> Result<Vec<AuthEffect>, AuthError> {
        let method = packet.method.ok_or(AuthError::MissingMethod)?;
        let (response, context) = match method {
            EapMethod::Identity => (
                encode_response(
                    packet.identifier,
                    EapMethod::Identity,
                    self.credentials.identity(),
                ),
                RequestContext::Identity,
            ),
            EapMethod::Md5Challenge => {
                let challenge = parse_md5_challenge(&packet.payload)?;
                (
                    self.md5_response(packet.identifier, &challenge),
                    RequestContext::Md5Challenge { challenge },
                )
            }
            EapMethod::RuijiePrivate => {
                let payload = self.private_pap_payload()?;
                (
                    encode_response(packet.identifier, EapMethod::RuijiePrivate, &payload),
                    RequestContext::RuijiePrivate,
                )
            }
            EapMethod::Notification => (
                encode_response(packet.identifier, EapMethod::Notification, &[]),
                RequestContext::Notification,
            ),
            _unsupported => {
                let preferred = [
                    u8::from(EapMethod::Md5Challenge),
                    u8::from(EapMethod::RuijiePrivate),
                ];
                (
                    encode_response(packet.identifier, EapMethod::Nak, &preferred),
                    RequestContext::Nak { requested: method },
                )
            }
        };
        let response = response?;
        self.last_identifier = Some(packet.identifier);
        self.state = AuthState::Authenticating;
        Ok(vec![
            AuthEffect::CancelTimer(TimerKind::Start),
            AuthEffect::SendEap {
                packet: response,
                context,
            },
            AuthEffect::ArmTimer {
                kind: TimerKind::Authentication,
                duration: self.policy.authentication_timeout,
            },
        ])
    }

    fn md5_response(&self, identifier: u8, challenge: &Md5Challenge) -> Result<Vec<u8>, AuthError> {
        let digest = md5_response::calculate(
            identifier,
            self.credentials.password(),
            challenge.as_bytes(),
        );
        let mut response_payload =
            Vec::with_capacity(1 + digest.len() + self.credentials.identity().len());
        response_payload.push(md5_response::MD5_CHALLENGE_LENGTH_WIRE);
        response_payload.extend_from_slice(&digest);
        response_payload.extend_from_slice(self.credentials.identity());
        encode_response(identifier, EapMethod::Md5Challenge, &response_payload)
    }

    fn private_pap_payload(&self) -> Result<Vec<u8>, AuthError> {
        let mut payload = Vec::with_capacity(
            1 + self.credentials.password().len() + self.credentials.identity().len(),
        );
        let password_length = u8::try_from(self.credentials.password().len())
            .map_err(|_error| AuthError::CredentialLengthInvariant)?;
        payload.push(password_length);
        payload.extend_from_slice(self.credentials.password());
        payload.extend_from_slice(self.credentials.identity());
        Ok(payload)
    }

    fn handle_timer(&mut self, kind: TimerKind) -> Result<Vec<AuthEffect>, AuthError> {
        match (self.state, kind) {
            (AuthState::AwaitingRequest, TimerKind::Start) => {
                Ok(self.enter_held(FailureReason::StartTimeout))
            }
            (AuthState::Authenticating, TimerKind::Authentication) => {
                Ok(self.enter_held(FailureReason::AuthenticationTimeout))
            }
            (AuthState::Held, TimerKind::Held) => {
                if self.attempts >= self.policy.maximum_attempts {
                    self.state = AuthState::Terminated;
                    Ok(vec![AuthEffect::Terminated {
                        reason: Some(FailureReason::RetryExhausted),
                    }])
                } else {
                    self.attempts += 1;
                    self.last_identifier = None;
                    self.state = AuthState::AwaitingRequest;
                    Ok(self.start_effects())
                }
            }
            (state, _) => Err(AuthError::InvalidEvent {
                event: "timer expiration",
                state,
            }),
        }
    }

    fn enter_held(&mut self, reason: FailureReason) -> Vec<AuthEffect> {
        let will_retry = self.attempts < self.policy.maximum_attempts;
        self.state = AuthState::Held;
        vec![
            AuthEffect::CancelTimer(TimerKind::Start),
            AuthEffect::CancelTimer(TimerKind::Authentication),
            AuthEffect::Failed { reason, will_retry },
            AuthEffect::ArmTimer {
                kind: TimerKind::Held,
                duration: self.policy.held_duration,
            },
        ]
    }

    fn start_effects(&self) -> Vec<AuthEffect> {
        vec![
            AuthEffect::SendStart,
            AuthEffect::ArmTimer {
                kind: TimerKind::Start,
                duration: self.policy.start_timeout,
            },
        ]
    }

    fn stop(&mut self) -> Vec<AuthEffect> {
        if self.state == AuthState::Terminated {
            return Vec::new();
        }
        let send_logoff = !matches!(self.state, AuthState::Idle | AuthState::Held);
        self.state = AuthState::Terminated;
        let mut effects = vec![
            AuthEffect::CancelTimer(TimerKind::Start),
            AuthEffect::CancelTimer(TimerKind::Authentication),
            AuthEffect::CancelTimer(TimerKind::Held),
        ];
        if send_logoff {
            effects.push(AuthEffect::SendLogoff);
        }
        effects.push(AuthEffect::Terminated { reason: None });
        effects
    }
}

fn parse_md5_challenge(payload: &[u8]) -> Result<Md5Challenge, AuthError> {
    let Some((&declared_length, remainder)) = payload.split_first() else {
        return Err(AuthError::InvalidMd5ChallengeLength { actual: 0 });
    };
    let declared_length = usize::from(declared_length);
    if declared_length != md5_response::MD5_CHALLENGE_LENGTH {
        return Err(AuthError::InvalidMd5ChallengeLength {
            actual: declared_length,
        });
    }
    let Some(challenge) = remainder.get(..md5_response::MD5_CHALLENGE_LENGTH) else {
        return Err(AuthError::InvalidMd5ChallengeLength {
            actual: remainder.len(),
        });
    };
    let mut bytes = [0; md5_response::MD5_CHALLENGE_LENGTH];
    bytes.copy_from_slice(challenge);
    Ok(Md5Challenge(bytes))
}

fn encode_response(
    identifier: u8,
    method: EapMethod,
    payload: &[u8],
) -> Result<Vec<u8>, AuthError> {
    EapPacket::response(identifier, method, payload)
        .encode()
        .map_err(|error| AuthError::Codec(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rjconnect_eapol::{EapMethod, EapPacket};

    use super::*;

    fn machine() -> Result<AuthMachine, Box<dyn Error>> {
        let credentials = Credentials::new(b"student".to_vec(), b"secret".to_vec())?;
        Ok(AuthMachine::new(credentials, SessionPolicy::default()))
    }

    fn request(
        machine: &mut AuthMachine,
        identifier: u8,
        method: EapMethod,
        payload: Vec<u8>,
    ) -> Result<Vec<AuthEffect>, AuthError> {
        machine.handle(AuthEvent::Eap(IncomingEap {
            code: EapCode::Request,
            identifier,
            method: Some(method),
            payload,
        }))
    }

    #[test]
    fn start_emits_start_and_timer() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;

        assert_eq!(
            machine.handle(AuthEvent::Start)?,
            [
                AuthEffect::SendStart,
                AuthEffect::ArmTimer {
                    kind: TimerKind::Start,
                    duration: Duration::from_secs(3),
                },
            ]
        );
        assert_eq!(machine.state(), AuthState::AwaitingRequest);
        Ok(())
    }

    #[test]
    fn identity_request_returns_identity_response() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;
        let effects = machine.handle(AuthEvent::Eap(IncomingEap {
            code: EapCode::Request,
            identifier: 4,
            method: Some(EapMethod::Identity),
            payload: Vec::new(),
        }))?;
        let AuthEffect::SendEap {
            packet: encoded,
            context,
        } = &effects[1]
        else {
            return Err("missing EAP response".into());
        };
        let packet = EapPacket::parse(encoded)?;

        assert_eq!(packet.code, EapCode::Response);
        assert_eq!(packet.identifier, 4);
        assert_eq!(packet.method, Some(EapMethod::Identity));
        assert_eq!(packet.payload, b"student");
        assert_eq!(*context, RequestContext::Identity);
        assert_eq!(machine.state(), AuthState::Authenticating);
        Ok(())
    }

    #[test]
    fn md5_request_matches_independent_vector() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;
        let mut payload = vec![16];
        payload.extend(0_u8..16);
        let effects = machine.handle(AuthEvent::Eap(IncomingEap {
            code: EapCode::Request,
            identifier: 7,
            method: Some(EapMethod::Md5Challenge),
            payload,
        }))?;
        let AuthEffect::SendEap {
            packet: encoded,
            context,
        } = &effects[1]
        else {
            return Err("missing EAP response".into());
        };
        let packet = EapPacket::parse(encoded)?;

        assert_eq!(packet.payload[0], 16);
        assert_eq!(
            &packet.payload[1..17],
            [
                0x82, 0x16, 0x43, 0x66, 0x5b, 0x43, 0x03, 0x59, 0xe5, 0x2a, 0xc5, 0x24, 0xd2, 0x9c,
                0x8f, 0x95,
            ]
        );
        assert_eq!(&packet.payload[17..], b"student");
        let RequestContext::Md5Challenge { challenge } = context else {
            return Err("missing MD5 challenge context".into());
        };
        assert_eq!(
            challenge.as_bytes(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(format!("{challenge:?}"), "Md5Challenge(<redacted>)");
        Ok(())
    }

    #[test]
    fn malformed_md5_request_does_not_advance_state() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;

        assert_eq!(
            machine.handle(AuthEvent::Eap(IncomingEap {
                code: EapCode::Request,
                identifier: 1,
                method: Some(EapMethod::Md5Challenge),
                payload: vec![16, 1, 2],
            })),
            Err(AuthError::InvalidMd5ChallengeLength { actual: 2 })
        );
        assert_eq!(machine.state(), AuthState::AwaitingRequest);
        Ok(())
    }

    #[test]
    fn private_request_encodes_length_password_and_identity() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;
        let effects = request(&mut machine, 5, EapMethod::RuijiePrivate, Vec::new())?;
        let AuthEffect::SendEap {
            packet: encoded,
            context,
        } = &effects[1]
        else {
            return Err("missing private EAP response".into());
        };
        let packet = EapPacket::parse(encoded)?;

        assert_eq!(packet.method, Some(EapMethod::RuijiePrivate));
        assert_eq!(packet.payload[0], 6);
        assert_eq!(&packet.payload[1..7], b"secret");
        assert_eq!(&packet.payload[7..], b"student");
        assert_eq!(*context, RequestContext::RuijiePrivate);
        Ok(())
    }

    #[test]
    fn unsupported_request_returns_nak_with_supported_methods() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;
        let effects = request(&mut machine, 6, EapMethod::Tls, Vec::new())?;
        let AuthEffect::SendEap {
            packet: encoded,
            context,
        } = &effects[1]
        else {
            return Err("missing NAK response".into());
        };
        let packet = EapPacket::parse(encoded)?;

        assert_eq!(packet.method, Some(EapMethod::Nak));
        assert_eq!(packet.payload, [4, 7]);
        assert_eq!(
            *context,
            RequestContext::Nak {
                requested: EapMethod::Tls,
            }
        );
        Ok(())
    }

    #[test]
    fn success_requires_the_latest_request_identifier() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;
        request(&mut machine, 9, EapMethod::Identity, Vec::new())?;

        assert_eq!(
            machine.handle(AuthEvent::Eap(IncomingEap {
                code: EapCode::Success,
                identifier: 10,
                method: None,
                payload: Vec::new(),
            })),
            Err(AuthError::UnexpectedIdentifier {
                expected: 9,
                actual: 10,
            })
        );
        assert_eq!(machine.state(), AuthState::Authenticating);
        assert_eq!(
            machine.handle(AuthEvent::Eap(IncomingEap {
                code: EapCode::Success,
                identifier: 9,
                method: None,
                payload: Vec::new(),
            }))?,
            [
                AuthEffect::CancelTimer(TimerKind::Start),
                AuthEffect::CancelTimer(TimerKind::Authentication),
                AuthEffect::Authenticated,
            ]
        );
        assert_eq!(machine.state(), AuthState::Authenticated);
        Ok(())
    }

    #[test]
    fn result_before_any_request_is_rejected() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;

        assert_eq!(
            machine.handle(AuthEvent::Eap(IncomingEap {
                code: EapCode::Failure,
                identifier: 1,
                method: None,
                payload: Vec::new(),
            })),
            Err(AuthError::InvalidEvent {
                event: "EAP result before request",
                state: AuthState::AwaitingRequest,
            })
        );
        Ok(())
    }

    #[test]
    fn start_timeout_enters_held_with_retry() -> Result<(), Box<dyn Error>> {
        let mut machine = machine()?;
        machine.handle(AuthEvent::Start)?;
        let effects = machine.handle(AuthEvent::TimerExpired(TimerKind::Start))?;

        assert!(effects.contains(&AuthEffect::Failed {
            reason: FailureReason::StartTimeout,
            will_retry: true,
        }));
        assert!(effects.contains(&AuthEffect::ArmTimer {
            kind: TimerKind::Held,
            duration: Duration::from_secs(3),
        }));
        assert_eq!(machine.state(), AuthState::Held);
        Ok(())
    }

    #[test]
    fn stop_is_idempotent_and_sends_logoff_only_for_active_session() -> Result<(), Box<dyn Error>> {
        let mut idle = machine()?;
        let idle_effects = idle.handle(AuthEvent::Stop)?;
        assert!(!idle_effects.contains(&AuthEffect::SendLogoff));
        assert!(idle.handle(AuthEvent::Stop)?.is_empty());

        let mut active = machine()?;
        active.handle(AuthEvent::Start)?;
        assert!(
            active
                .handle(AuthEvent::Stop)?
                .contains(&AuthEffect::SendLogoff)
        );
        assert_eq!(active.state(), AuthState::Terminated);
        Ok(())
    }

    #[test]
    fn policy_rejects_zero_values() {
        assert_eq!(
            SessionPolicy::new(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1),
                1,
            ),
            Err(AuthError::InvalidPolicy)
        );
        assert_eq!(
            SessionPolicy::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                0,
            ),
            Err(AuthError::InvalidPolicy)
        );
    }

    #[test]
    fn failure_retries_until_budget_is_exhausted() -> Result<(), Box<dyn Error>> {
        let credentials = Credentials::new(b"student".to_vec(), b"secret".to_vec())?;
        let policy = SessionPolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            2,
        )?;
        let mut machine = AuthMachine::new(credentials, policy);
        machine.handle(AuthEvent::Start)?;
        request(&mut machine, 1, EapMethod::Identity, Vec::new())?;
        machine.handle(AuthEvent::Eap(IncomingEap {
            code: EapCode::Failure,
            identifier: 1,
            method: None,
            payload: Vec::new(),
        }))?;
        machine.handle(AuthEvent::TimerExpired(TimerKind::Held))?;
        request(&mut machine, 2, EapMethod::Identity, Vec::new())?;
        machine.handle(AuthEvent::Eap(IncomingEap {
            code: EapCode::Failure,
            identifier: 2,
            method: None,
            payload: Vec::new(),
        }))?;

        assert_eq!(
            machine.handle(AuthEvent::TimerExpired(TimerKind::Held))?,
            [AuthEffect::Terminated {
                reason: Some(FailureReason::RetryExhausted),
            }]
        );
        assert_eq!(machine.state(), AuthState::Terminated);
        Ok(())
    }
}
