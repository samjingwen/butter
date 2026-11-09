use crate::{
    Authority, Credential, Principal, SecurityContext, SecurityEvent, SecurityEventSink,
    events::AuthenticationEvent,
};
use std::{
    any::Any, collections::BTreeSet, error::Error, fmt, future::Future, pin::Pin, sync::Arc,
    time::SystemTime,
};
use zeroize::Zeroize;

const MAX_MECHANISM_BYTES: usize = 64;
const MAX_AUTHORITIES: usize = 256;
const MAX_PROVIDERS: usize = 64;

/// Sanitized construction failure for authentication values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationBuildError {
    /// An authentication mechanism was empty, too long or not a safe identifier.
    InvalidMechanism,
    /// An assurance level was outside the supported non-zero range.
    InvalidAssuranceLevel,
    /// An authenticated result exceeded the authority count bound.
    AuthorityLimit,
}

impl fmt::Display for AuthenticationBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMechanism => "invalid authentication mechanism",
            Self::InvalidAssuranceLevel => "invalid authentication assurance level",
            Self::AuthorityLimit => "authentication authority limit exceeded",
        })
    }
}

impl Error for AuthenticationBuildError {}

/// Validated, non-secret name of an authentication mechanism.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthenticationMechanism(Arc<str>);

impl AuthenticationMechanism {
    /// Validates a mechanism name.
    ///
    /// Names contain 1-64 ASCII alphanumeric, dot, underscore or hyphen bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthenticationBuildError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_MECHANISM_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if !valid {
            return Err(AuthenticationBuildError::InvalidMechanism);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the mechanism name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Ordered assurance value assigned by the authenticating application.
///
/// Butter compares levels but does not assign protocol meaning to values beyond
/// the two convenience constants. Applications must use one consistent scale.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssuranceLevel(u8);

impl AssuranceLevel {
    /// Conventional level for one completed authentication factor.
    pub const SINGLE_FACTOR: Self = Self(1);
    /// Conventional level for multiple independently completed factors.
    pub const MULTI_FACTOR: Self = Self(2);

    /// Creates a non-zero assurance level.
    pub fn new(value: u8) -> Result<Self, AuthenticationBuildError> {
        if value == 0 {
            return Err(AuthenticationBuildError::InvalidAssuranceLevel);
        }
        Ok(Self(value))
    }

    /// Returns the numeric assurance level.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Authentication assurance recorded in a successful result.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Assurance {
    level: AssuranceLevel,
}

impl Assurance {
    /// Creates assurance at the supplied application-defined level.
    #[must_use]
    pub const fn new(level: AssuranceLevel) -> Self {
        Self { level }
    }

    /// Returns the ordered assurance level.
    #[must_use]
    pub const fn level(self) -> AssuranceLevel {
        self.level
    }
}

/// Credential-free statement produced by a successful provider.
#[derive(Clone)]
pub struct Authentication {
    principal: Arc<dyn Principal>,
    authorities: BTreeSet<Authority>,
    mechanism: AuthenticationMechanism,
    authenticated_at: SystemTime,
    assurance: Assurance,
}

impl Authentication {
    /// Starts explicit construction of an authenticated result.
    #[must_use]
    pub fn builder(
        principal: Arc<dyn Principal>,
        mechanism: AuthenticationMechanism,
        authenticated_at: SystemTime,
        assurance: Assurance,
    ) -> AuthenticationBuilder {
        AuthenticationBuilder {
            principal,
            authorities: BTreeSet::new(),
            mechanism,
            authenticated_at,
            assurance,
        }
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub fn principal(&self) -> &dyn Principal {
        self.principal.as_ref()
    }

    /// Returns exact, case-sensitive authorities.
    pub fn authorities(&self) -> impl ExactSizeIterator<Item = &Authority> {
        self.authorities.iter()
    }

    /// Reports whether the exact authority is present.
    #[must_use]
    pub fn has_authority(&self, authority: &Authority) -> bool {
        self.authorities.contains(authority)
    }

    /// Returns the successful mechanism.
    #[must_use]
    pub fn mechanism(&self) -> &AuthenticationMechanism {
        &self.mechanism
    }

    /// Returns the time supplied by the successful provider.
    #[must_use]
    pub const fn authenticated_at(&self) -> SystemTime {
        self.authenticated_at
    }

    /// Returns the application-assigned assurance.
    #[must_use]
    pub const fn assurance(&self) -> Assurance {
        self.assurance
    }

    /// Creates an immutable request-scoped security context.
    #[must_use]
    pub fn into_context(self) -> SecurityContext {
        SecurityContext::authenticated(self)
    }
}

impl fmt::Debug for Authentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authentication")
            .field("subject", self.principal.subject())
            .field("authorities", &self.authorities)
            .field("mechanism", &self.mechanism)
            .field("authenticated_at", &self.authenticated_at)
            .field("assurance", &self.assurance)
            .finish()
    }
}

/// Explicit builder for a credential-free authenticated result.
pub struct AuthenticationBuilder {
    principal: Arc<dyn Principal>,
    authorities: BTreeSet<Authority>,
    mechanism: AuthenticationMechanism,
    authenticated_at: SystemTime,
    assurance: Assurance,
}

impl AuthenticationBuilder {
    /// Adds an exact authority, ignoring a duplicate.
    pub fn authority(
        &mut self,
        authority: Authority,
    ) -> Result<&mut Self, AuthenticationBuildError> {
        if !self.authorities.contains(&authority) && self.authorities.len() == MAX_AUTHORITIES {
            return Err(AuthenticationBuildError::AuthorityLimit);
        }
        self.authorities.insert(authority);
        Ok(self)
    }

    /// Completes the immutable authenticated result.
    #[must_use]
    pub fn build(self) -> Authentication {
        Authentication {
            principal: self.principal,
            authorities: self.authorities,
            mechanism: self.mechanism,
            authenticated_at: self.authenticated_at,
            assurance: self.assurance,
        }
    }
}

/// Object-safe credential-bearing request accepted by authentication managers.
///
/// The trait deliberately has no formatting or cloning requirement. Providers
/// use [`AuthenticationRequest::as_any`] to recognize typed request families.
/// Implementations must own bounded credentials in a redacting, zeroizing type
/// and must not expose them through formatting or errors.
///
/// ```
/// use butter_security::{AuthenticationMechanism, AuthenticationRequest, Credential};
/// use std::any::Any;
///
/// struct TokenRequest {
///     mechanism: AuthenticationMechanism,
///     token: Credential<String>,
/// }
///
/// impl AuthenticationRequest for TokenRequest {
///     fn mechanism(&self) -> &AuthenticationMechanism { &self.mechanism }
///     fn as_any(&self) -> &dyn Any { self }
/// }
/// ```
pub trait AuthenticationRequest: Any + Send + Sync {
    /// Returns the non-secret mechanism selected during credential extraction.
    fn mechanism(&self) -> &AuthenticationMechanism;

    /// Exposes the concrete request for typed provider downcasting.
    fn as_any(&self) -> &dyn Any;
}

impl dyn AuthenticationRequest {
    /// Attempts to recover the concrete credential request type.
    #[must_use]
    pub fn downcast_ref<R: AuthenticationRequest>(&self) -> Option<&R> {
        self.as_any().downcast_ref()
    }
}

/// Generic typed authentication request with redacted, zeroizing credentials.
pub struct CredentialRequest<C: Zeroize> {
    mechanism: AuthenticationMechanism,
    credential: Credential<C>,
}

impl<C: Zeroize> CredentialRequest<C> {
    /// Creates a typed request for a validated mechanism.
    #[must_use]
    pub fn new(mechanism: AuthenticationMechanism, credential: C) -> Self {
        Self {
            mechanism,
            credential: Credential::new(credential),
        }
    }

    /// Deliberately exposes credentials to a provider that recognizes this type.
    #[must_use]
    pub fn credential(&self) -> &C {
        self.credential.expose_secret()
    }
}

impl<C: Zeroize> fmt::Debug for CredentialRequest<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRequest")
            .field("mechanism", &self.mechanism)
            .field("credential", &self.credential)
            .finish()
    }
}

impl<C> AuthenticationRequest for CredentialRequest<C>
where
    C: Zeroize + Send + Sync + 'static,
{
    fn mechanism(&self) -> &AuthenticationMechanism {
        &self.mechanism
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Credential rejection category safe to expose to framework policy and events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationRejection {
    /// Presented credentials were not accepted.
    InvalidCredentials,
    /// The recognized authentication attempt is not permitted by provider policy.
    NotPermitted,
}

/// Credential-free operational failure category from a provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationOperationalError {
    /// A required verifier or identity source was unavailable.
    Unavailable,
    /// Verification exceeded an application-owned deadline.
    TimedOut,
    /// Verification failed for another non-credential internal reason.
    Internal,
}

impl fmt::Display for AuthenticationOperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authentication dependency unavailable",
            Self::TimedOut => "authentication verification timed out",
            Self::Internal => "authentication verification failed",
        })
    }
}

impl Error for AuthenticationOperationalError {}

/// Terminal authentication-manager failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationFailure {
    /// A provider recognized and rejected the request.
    Rejected(AuthenticationRejection),
    /// Every configured provider abstained from the request mechanism.
    UnsupportedMechanism,
    /// A provider encountered an operational failure.
    Operational(AuthenticationOperationalError),
}

impl fmt::Display for AuthenticationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Rejected(_) => "authentication rejected",
            Self::UnsupportedMechanism => "unsupported authentication mechanism",
            Self::Operational(_) => "authentication operation failed",
        })
    }
}

impl Error for AuthenticationFailure {}

/// Result of one provider's recognition and verification attempt.
#[derive(Clone, Debug)]
pub enum ProviderOutcome {
    /// The request was recognized and successfully authenticated.
    Authenticated(Authentication),
    /// The request does not belong to this provider.
    Unsupported,
    /// The request was recognized and rejected, so fallback must stop.
    Rejected(AuthenticationRejection),
}

/// Boxed provider future used to keep heterogeneous providers object-safe.
pub type ProviderFuture<'a> = Pin<
    Box<dyn Future<Output = Result<ProviderOutcome, AuthenticationOperationalError>> + Send + 'a>,
>;

/// Credential verifier for one or more typed authentication request families.
///
/// A provider returns `Unsupported` without reading unknown credentials,
/// `Rejected` after recognizing invalid credentials, or a credential-free
/// [`Authentication`] after success. Operational failures use the outer
/// `Result`. Dropping the returned future must release borrowed credentials;
/// detached verifier work is the provider's explicit responsibility.
///
/// ```
/// use butter_security::{
///     AuthenticationOperationalError, AuthenticationProvider, AuthenticationRequest,
///     CredentialRequest, ProviderFuture, ProviderOutcome,
/// };
///
/// struct TextCredentialProvider;
///
/// impl AuthenticationProvider for TextCredentialProvider {
///     fn authenticate<'a>(
///         &'a self,
///         request: &'a dyn AuthenticationRequest,
///     ) -> ProviderFuture<'a> {
///         let supported = request.downcast_ref::<CredentialRequest<String>>().is_some();
///         Box::pin(async move {
///             if supported {
///                 Err(AuthenticationOperationalError::Unavailable)
///             } else {
///                 Ok(ProviderOutcome::Unsupported)
///             }
///         })
///     }
/// }
/// ```
pub trait AuthenticationProvider: Send + Sync {
    /// Recognizes and verifies a request without cloning its credentials.
    fn authenticate<'a>(&'a self, request: &'a dyn AuthenticationRequest) -> ProviderFuture<'a>;
}

/// Boxed authentication-manager future.
pub type AuthenticationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Authentication, AuthenticationFailure>> + Send + 'a>>;

/// Stable entry point for credential verification.
///
/// Implementations return credential-free success or a typed, sanitized
/// failure. Dropping the future cancels in-progress orchestration by dropping
/// its active provider future, but cannot stop work a provider detached.
///
/// ```
/// use butter_security::{
///     AuthenticationFailure, AuthenticationFuture, AuthenticationManager,
///     AuthenticationRequest,
/// };
///
/// struct DisabledAuthentication;
///
/// impl AuthenticationManager for DisabledAuthentication {
///     fn authenticate<'a>(
///         &'a self,
///         _request: &'a dyn AuthenticationRequest,
///     ) -> AuthenticationFuture<'a> {
///         Box::pin(async { Err(AuthenticationFailure::UnsupportedMechanism) })
///     }
/// }
/// ```
pub trait AuthenticationManager: Send + Sync {
    /// Authenticates one request through the configured strategy.
    fn authenticate<'a>(
        &'a self,
        request: &'a dyn AuthenticationRequest,
    ) -> AuthenticationFuture<'a>;
}

/// Sanitized provider-manager construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderManagerBuildError {
    /// At least one provider is required.
    NoProviders,
    /// One manager accepts at most 64 providers.
    ProviderLimit,
}

impl fmt::Display for ProviderManagerBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoProviders => "authentication provider manager requires a provider",
            Self::ProviderLimit => "authentication provider limit exceeded",
        })
    }
}

impl Error for ProviderManagerBuildError {}

/// Builder for ordered authentication-provider orchestration.
#[derive(Default)]
pub struct ProviderManagerBuilder {
    providers: Vec<Arc<dyn AuthenticationProvider>>,
    event_sink: Option<Arc<dyn SecurityEventSink>>,
}

impl ProviderManagerBuilder {
    /// Adds a provider at the end of the evaluation order.
    pub fn provider(
        &mut self,
        provider: Arc<dyn AuthenticationProvider>,
    ) -> Result<&mut Self, ProviderManagerBuildError> {
        if self.providers.len() == MAX_PROVIDERS {
            return Err(ProviderManagerBuildError::ProviderLimit);
        }
        self.providers.push(provider);
        Ok(self)
    }

    /// Installs the optional synchronous, credential-free event sink.
    ///
    /// The sink must be non-blocking and must not panic.
    pub fn event_sink(&mut self, sink: Arc<dyn SecurityEventSink>) -> &mut Self {
        self.event_sink = Some(sink);
        self
    }

    /// Validates and constructs the provider manager.
    pub fn build(self) -> Result<ProviderManager, ProviderManagerBuildError> {
        if self.providers.is_empty() {
            return Err(ProviderManagerBuildError::NoProviders);
        }
        Ok(ProviderManager {
            providers: self.providers,
            event_sink: self.event_sink,
        })
    }
}

/// Ordered provider manager with terminal rejection and operational failure.
pub struct ProviderManager {
    providers: Vec<Arc<dyn AuthenticationProvider>>,
    event_sink: Option<Arc<dyn SecurityEventSink>>,
}

impl ProviderManager {
    /// Creates an empty explicit builder.
    #[must_use]
    pub fn builder() -> ProviderManagerBuilder {
        ProviderManagerBuilder::default()
    }

    fn publish(&self, event: AuthenticationEvent) {
        if let Some(sink) = &self.event_sink {
            sink.publish(SecurityEvent::Authentication(event));
        }
    }
}

impl AuthenticationManager for ProviderManager {
    fn authenticate<'a>(
        &'a self,
        request: &'a dyn AuthenticationRequest,
    ) -> AuthenticationFuture<'a> {
        Box::pin(async move {
            for provider in &self.providers {
                match provider.authenticate(request).await {
                    Ok(ProviderOutcome::Authenticated(authentication)) => {
                        self.publish(AuthenticationEvent::success(&authentication));
                        return Ok(authentication);
                    }
                    Ok(ProviderOutcome::Unsupported) => {}
                    Ok(ProviderOutcome::Rejected(rejection)) => {
                        self.publish(AuthenticationEvent::rejected(
                            request.mechanism().clone(),
                            rejection,
                        ));
                        return Err(AuthenticationFailure::Rejected(rejection));
                    }
                    Err(error) => {
                        self.publish(AuthenticationEvent::operational_failure(
                            request.mechanism().clone(),
                            error,
                        ));
                        return Err(AuthenticationFailure::Operational(error));
                    }
                }
            }

            self.publish(AuthenticationEvent::unsupported(
                request.mechanism().clone(),
            ));
            Err(AuthenticationFailure::UnsupportedMechanism)
        })
    }
}
