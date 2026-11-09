use crate::{
    Assurance, Authentication, AuthenticationMechanism, AuthenticationOperationalError,
    AuthenticationRejection, AuthorizationDecision, SubjectId,
};
use std::time::SystemTime;

/// Credential-free successful authentication event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationSuccessEvent {
    subject: SubjectId,
    mechanism: AuthenticationMechanism,
    authenticated_at: SystemTime,
    assurance: Assurance,
}

impl AuthenticationSuccessEvent {
    /// Returns the authenticated subject.
    #[must_use]
    pub fn subject(&self) -> &SubjectId {
        &self.subject
    }

    /// Returns the successful mechanism.
    #[must_use]
    pub fn mechanism(&self) -> &AuthenticationMechanism {
        &self.mechanism
    }

    /// Returns the provider-supplied authentication time.
    #[must_use]
    pub const fn authenticated_at(&self) -> SystemTime {
        self.authenticated_at
    }

    /// Returns the provider-supplied assurance.
    #[must_use]
    pub const fn assurance(&self) -> Assurance {
        self.assurance
    }
}

/// Credential-free recognized rejection event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRejectedEvent {
    mechanism: AuthenticationMechanism,
    rejection: AuthenticationRejection,
}

impl AuthenticationRejectedEvent {
    /// Returns the recognized mechanism.
    #[must_use]
    pub fn mechanism(&self) -> &AuthenticationMechanism {
        &self.mechanism
    }

    /// Returns the sanitized rejection category.
    #[must_use]
    pub const fn rejection(&self) -> AuthenticationRejection {
        self.rejection
    }
}

/// Credential-free unsupported-mechanism event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationUnsupportedEvent {
    mechanism: AuthenticationMechanism,
}

impl AuthenticationUnsupportedEvent {
    /// Returns the mechanism unsupported by every configured provider.
    #[must_use]
    pub fn mechanism(&self) -> &AuthenticationMechanism {
        &self.mechanism
    }
}

/// Credential-free provider operational-failure event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationOperationalFailureEvent {
    mechanism: AuthenticationMechanism,
    error: AuthenticationOperationalError,
}

impl AuthenticationOperationalFailureEvent {
    /// Returns the selected mechanism.
    #[must_use]
    pub fn mechanism(&self) -> &AuthenticationMechanism {
        &self.mechanism
    }

    /// Returns the sanitized operational category.
    #[must_use]
    pub const fn error(&self) -> AuthenticationOperationalError {
        self.error
    }
}

/// Typed, credential-free authentication event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationEvent {
    /// A provider successfully authenticated the request.
    Succeeded(AuthenticationSuccessEvent),
    /// A recognizing provider terminally rejected the request.
    Rejected(AuthenticationRejectedEvent),
    /// Every provider reported that the request was unsupported.
    Unsupported(AuthenticationUnsupportedEvent),
    /// A provider encountered an operational failure.
    OperationalFailure(AuthenticationOperationalFailureEvent),
}

impl AuthenticationEvent {
    pub(crate) fn success(authentication: &Authentication) -> Self {
        Self::Succeeded(AuthenticationSuccessEvent {
            subject: authentication.principal().subject().clone(),
            mechanism: authentication.mechanism().clone(),
            authenticated_at: authentication.authenticated_at(),
            assurance: authentication.assurance(),
        })
    }

    pub(crate) fn rejected(
        mechanism: AuthenticationMechanism,
        rejection: AuthenticationRejection,
    ) -> Self {
        Self::Rejected(AuthenticationRejectedEvent {
            mechanism,
            rejection,
        })
    }

    pub(crate) fn unsupported(mechanism: AuthenticationMechanism) -> Self {
        Self::Unsupported(AuthenticationUnsupportedEvent { mechanism })
    }

    pub(crate) fn operational_failure(
        mechanism: AuthenticationMechanism,
        error: AuthenticationOperationalError,
    ) -> Self {
        Self::OperationalFailure(AuthenticationOperationalFailureEvent { mechanism, error })
    }
}

/// Credential-free authorization decision event supplied by an application.
///
/// Core authorization does not publish automatically because the application
/// owns the bounded policy identity and event-volume policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationEvent {
    decision: AuthorizationDecision,
    subject: Option<SubjectId>,
}

impl AuthorizationEvent {
    /// Creates an event from a decision and optional authenticated subject.
    #[must_use]
    pub const fn new(decision: AuthorizationDecision, subject: Option<SubjectId>) -> Self {
        Self { decision, subject }
    }

    /// Returns the authorization decision.
    #[must_use]
    pub const fn decision(&self) -> AuthorizationDecision {
        self.decision
    }

    /// Returns the authenticated subject when one participated.
    #[must_use]
    pub fn subject(&self) -> Option<&SubjectId> {
        self.subject.as_ref()
    }
}

/// Generic security event accepted by an application-owned sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityEvent {
    /// Authentication orchestration event.
    Authentication(AuthenticationEvent),
    /// Authorization decision event published explicitly by an application.
    Authorization(AuthorizationEvent),
}

/// Synchronous sink for bounded, credential-free security events.
///
/// Implementations must return quickly and must not panic. Durable audit writes
/// belong in application transactions rather than this notification seam.
///
/// ```
/// use butter_security::{SecurityEvent, SecurityEventSink};
/// use std::sync::atomic::{AtomicUsize, Ordering};
///
/// #[derive(Default)]
/// struct EventCounter(AtomicUsize);
///
/// impl SecurityEventSink for EventCounter {
///     fn publish(&self, _event: SecurityEvent) {
///         self.0.fetch_add(1, Ordering::Relaxed);
///     }
/// }
/// ```
pub trait SecurityEventSink: Send + Sync {
    /// Publishes one already-sanitized event.
    fn publish(&self, event: SecurityEvent);
}
