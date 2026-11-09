//! Transport-independent authentication and authorization contracts.
//!
//! Butter Security coordinates credential verification and fail-closed policy
//! decisions without owning identities, credentials, persistence or transport.
//! Authentication requests may contain credentials, while successful
//! [`Authentication`] and [`SecurityContext`] values cannot contain the request.
//! Contexts are ordinary immutable values intended to be attached explicitly to
//! one request. This crate has no thread-local or global security state.
//!
//! Provider cancellation is cooperative: dropping the future returned by an
//! [`AuthenticationManager`] drops the currently evaluated provider future.
//! It does not prove that work detached by an application provider has stopped.

mod authentication;
mod authorization;
mod context;
mod credential;
mod events;
mod identity;

pub use authentication::{
    Assurance, AssuranceLevel, Authentication, AuthenticationBuildError, AuthenticationBuilder,
    AuthenticationFailure, AuthenticationFuture, AuthenticationManager, AuthenticationMechanism,
    AuthenticationOperationalError, AuthenticationProvider, AuthenticationRejection,
    AuthenticationRequest, CredentialRequest, ProviderFuture, ProviderManager,
    ProviderManagerBuildError, ProviderManagerBuilder, ProviderOutcome,
};
pub use authorization::{
    AllAuthoritiesRequired, AllOf, AnonymousRequired, AnyAuthorityRequired, AnyOf,
    AuthenticatedRequired, AuthorityRequired, AuthorizationBuildError, AuthorizationDecision,
    AuthorizationFailure, AuthorizationFuture, AuthorizationManager, AuthorizationOperationalError,
    DenyAll, MinimumAssurance, Not, PermitAll, When, authorize,
};
pub use context::SecurityContext;
pub use credential::Credential;
pub use events::{
    AuthenticationEvent, AuthenticationOperationalFailureEvent, AuthenticationRejectedEvent,
    AuthenticationSuccessEvent, AuthenticationUnsupportedEvent, AuthorizationEvent, SecurityEvent,
    SecurityEventSink,
};
pub use identity::{Authority, DisplayName, IdentityError, NamedPrincipal, Principal, SubjectId};

#[cfg(test)]
mod tests;
