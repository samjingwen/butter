use crate::{CsrfProtection, RequestMetadata};
use butter_security::{Authentication, SecurityContext};
use butter_web::{
    browser::{
        BrowserCookie, CookieHeaderPolicy, CookieLifetime, CookieValue, CookieVisibility,
        SetCookieError, read_unchecked_cookie,
    },
    native::http::HeaderMap,
};
use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc};
use zeroize::Zeroize;

const MAX_SESSION_IDENTIFIER_BYTES: usize = 1_024;

/// Redacting, zeroizing opaque browser session identifier.
///
/// The value is validated for direct use as an unquoted cookie value. Butter
/// assigns no structure to it and never logs it.
pub struct SessionIdentifier(String);

impl SessionIdentifier {
    /// Validates a non-empty opaque identifier no larger than 1 KiB.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionIdentifierError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SESSION_IDENTIFIER_BYTES {
            return Err(SessionIdentifierError);
        }
        CookieValue::new(&value).map_err(|_| SessionIdentifierError)?;
        Ok(Self(value))
    }

    /// Deliberately exposes the opaque value to a session repository.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub(crate) fn cookie_value(&self) -> CookieValue<'_> {
        CookieValue::new(&self.0).expect("validated session identifier remains valid")
    }
}

impl fmt::Debug for SessionIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionIdentifier([REDACTED])")
    }
}

impl Zeroize for SessionIdentifier {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SessionIdentifier {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Sanitized invalid-session-identifier error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIdentifierError;

impl fmt::Display for SessionIdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid session identifier")
    }
}

impl Error for SessionIdentifierError {}

/// Explicit browser transport policy for an opaque session identifier.
///
/// The upstream cookie policy is fixed to host-only scope and root path. This
/// wrapper additionally requires `HttpOnly`; secure deployment or the explicit
/// loopback HTTP mode, `SameSite`, the cookie name, lifetime, and malformed
/// unrelated-cookie behavior all remain construction-time choices.
#[derive(Clone, Debug)]
pub struct SessionCookie {
    cookie: BrowserCookie,
    lifetime: CookieLifetime,
    header_policy: CookieHeaderPolicy,
}

impl SessionCookie {
    /// Creates a session-cookie policy that cannot be read by browser script.
    pub fn new(
        cookie: BrowserCookie,
        lifetime: CookieLifetime,
        header_policy: CookieHeaderPolicy,
    ) -> Result<Self, SessionConfigurationError> {
        if cookie.visibility() != CookieVisibility::HttpOnly {
            return Err(SessionConfigurationError::SessionCookieMustBeHttpOnly);
        }
        Ok(Self {
            cookie,
            lifetime,
            header_policy,
        })
    }

    /// Returns the validated upstream cookie policy.
    #[must_use]
    pub const fn cookie(&self) -> &BrowserCookie {
        &self.cookie
    }

    /// Returns the browser-side cookie lifetime.
    #[must_use]
    pub const fn lifetime(&self) -> CookieLifetime {
        self.lifetime
    }

    /// Returns malformed unrelated-cookie handling.
    #[must_use]
    pub const fn header_policy(&self) -> CookieHeaderPolicy {
        self.header_policy
    }

    pub(crate) fn read(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<SessionIdentifier>, SessionCookieReadError> {
        let value = read_unchecked_cookie(headers, self.cookie.name(), self.header_policy)
            .map_err(|_| SessionCookieReadError::Malformed)?;
        value
            .map(|value| {
                SessionIdentifier::new(value.as_str().to_owned())
                    .map_err(|_| SessionCookieReadError::Malformed)
            })
            .transpose()
    }

    pub(crate) fn append(
        &self,
        headers: &mut HeaderMap,
        identifier: &SessionIdentifier,
    ) -> Result<(), SetCookieError> {
        self.cookie
            .append(headers, identifier.cookie_value(), self.lifetime)
    }

    pub(crate) fn append_removal(&self, headers: &mut HeaderMap) -> Result<(), SetCookieError> {
        self.cookie.append_removal(headers)
    }
}

/// Invalid stateful-session configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionConfigurationError {
    /// Authentication cookies must always emit `HttpOnly`.
    SessionCookieMustBeHttpOnly,
}

impl fmt::Display for SessionConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("session cookie must be HttpOnly")
    }
}

impl Error for SessionConfigurationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionCookieReadError {
    Malformed,
}

/// Result of loading one presented session identifier.
pub enum SecurityContextLoad {
    /// No durable record currently belongs to the identifier.
    Missing,
    /// A record existed but is expired, revoked, or otherwise unusable.
    Invalid,
    /// An active authenticated request context was loaded.
    Active(SecurityContext),
}

impl fmt::Debug for SecurityContextLoad {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "SecurityContextLoad::Missing",
            Self::Invalid => "SecurityContextLoad::Invalid",
            Self::Active(_) => "SecurityContextLoad::Active([REDACTED])",
        })
    }
}

/// Sanitized failure of session strategy or repository work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionOperationError {
    /// A required durable dependency was unavailable.
    Unavailable,
    /// The operation exceeded an application-owned deadline.
    TimedOut,
    /// Persistence may or may not have committed and must not be replayed blindly.
    Unconfirmed,
    /// Another internal session operation failed.
    Internal,
}

impl fmt::Display for SessionOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "session dependency unavailable",
            Self::TimedOut => "session operation timed out",
            Self::Unconfirmed => "session persistence outcome is unconfirmed",
            Self::Internal => "session operation failed",
        })
    }
}

impl Error for SessionOperationError {}

/// Boxed context-load future.
pub type SecurityContextLoadFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SecurityContextLoad, SessionOperationError>> + Send + 'a>>;

/// Boxed session-write future.
pub type SessionWriteFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), SessionOperationError>> + Send + 'a>>;

/// Application-owned durable security-context storage.
///
/// `save` receives both identifiers during rotation so an implementation can
/// atomically create the replacement and make the previous identifier
/// unusable. A successful return is required before Butter emits the new
/// cookie. `Unconfirmed` means Butter will not emit it, but does not prove that
/// the durable write failed.
pub trait SecurityContextRepository: Send + Sync {
    /// Loads one request context without refreshing or rewriting it.
    fn load<'a>(
        &'a self,
        request: &'a RequestMetadata,
        identifier: &'a SessionIdentifier,
    ) -> SecurityContextLoadFuture<'a>;

    /// Persists a new identifier and context, replacing `previous` atomically.
    fn save<'a>(
        &'a self,
        request: &'a RequestMetadata,
        previous: Option<&'a SessionIdentifier>,
        identifier: &'a SessionIdentifier,
        context: &'a SecurityContext,
    ) -> SessionWriteFuture<'a>;

    /// Invalidates a presented identifier for logout or explicit revocation.
    fn invalidate<'a>(
        &'a self,
        request: &'a RequestMetadata,
        identifier: &'a SessionIdentifier,
    ) -> SessionWriteFuture<'a>;
}

/// Boxed session-identifier rotation future.
pub type SessionRotationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SessionIdentifier, SessionOperationError>> + Send + 'a>>;

/// Application-supplied fixation and elevation strategy.
///
/// Butter invokes this only for an approved authentication transition or an
/// explicit refresh. The returned identifier must be fresh; Butter rejects a
/// strategy that returns the currently presented value.
pub trait SessionAuthenticationStrategy: Send + Sync {
    /// Creates a fresh identifier for the authenticated context.
    fn rotate<'a>(
        &'a self,
        request: &'a RequestMetadata,
        previous: Option<&'a SessionIdentifier>,
        context: &'a SecurityContext,
    ) -> SessionRotationFuture<'a>;
}

pub(crate) enum CsrfDecision {
    Enabled(Arc<CsrfProtection>),
    Disabled,
}

/// Complete stateful browser-security configuration for one chain.
pub struct StatefulSecurity {
    pub(crate) repository: Arc<dyn SecurityContextRepository>,
    pub(crate) strategy: Arc<dyn SessionAuthenticationStrategy>,
    pub(crate) cookie: SessionCookie,
    pub(crate) csrf: CsrfDecision,
}

impl StatefulSecurity {
    /// Starts explicit stateful browser-security construction.
    #[must_use]
    pub fn builder() -> StatefulSecurityBuilder {
        StatefulSecurityBuilder::default()
    }

    /// Returns the authentication-cookie transport policy.
    #[must_use]
    pub const fn session_cookie(&self) -> &SessionCookie {
        &self.cookie
    }

    /// Reports whether CSRF and origin protection is enabled.
    #[must_use]
    pub const fn csrf_enabled(&self) -> bool {
        matches!(self.csrf, CsrfDecision::Enabled(_))
    }
}

/// Explicit builder for a stateful browser chain.
#[derive(Default)]
pub struct StatefulSecurityBuilder {
    repository: Option<Arc<dyn SecurityContextRepository>>,
    strategy: Option<Arc<dyn SessionAuthenticationStrategy>>,
    cookie: Option<SessionCookie>,
    csrf: Option<CsrfDecision>,
}

impl StatefulSecurityBuilder {
    /// Installs application-owned durable context persistence.
    pub fn context_repository(
        &mut self,
        repository: Arc<dyn SecurityContextRepository>,
    ) -> &mut Self {
        self.repository = Some(repository);
        self
    }

    /// Installs mandatory session-identifier rotation.
    pub fn session_authentication_strategy(
        &mut self,
        strategy: Arc<dyn SessionAuthenticationStrategy>,
    ) -> &mut Self {
        self.strategy = Some(strategy);
        self
    }

    /// Installs the explicit authentication-cookie policy.
    pub fn session_cookie(&mut self, cookie: SessionCookie) -> &mut Self {
        self.cookie = Some(cookie);
        self
    }

    /// Enables CSRF token and origin validation.
    pub fn csrf_protection(&mut self, protection: CsrfProtection) -> &mut Self {
        self.csrf = Some(CsrfDecision::Enabled(Arc::new(protection)));
        self
    }

    /// Explicitly disables CSRF and origin validation for this cookie chain.
    ///
    /// This weak setting is intentionally visible. Consuming applications must
    /// document why automatically attached browser credentials cannot reach an
    /// unsafe state change before selecting it.
    pub fn csrf_disabled(&mut self) -> &mut Self {
        self.csrf = Some(CsrfDecision::Disabled);
        self
    }

    /// Validates and completes stateful browser security.
    pub fn build(self) -> Result<StatefulSecurity, StatefulSecurityBuildError> {
        let cookie = self
            .cookie
            .ok_or(StatefulSecurityBuildError::MissingSessionCookie)?;
        let csrf = self
            .csrf
            .ok_or(StatefulSecurityBuildError::MissingCsrfDecision)?;
        if let CsrfDecision::Enabled(protection) = &csrf
            && protection.request_handler.cookie_name() == cookie.cookie().name()
        {
            return Err(StatefulSecurityBuildError::CookieNameCollision);
        }
        Ok(StatefulSecurity {
            repository: self
                .repository
                .ok_or(StatefulSecurityBuildError::MissingContextRepository)?,
            strategy: self
                .strategy
                .ok_or(StatefulSecurityBuildError::MissingSessionStrategy)?,
            cookie,
            csrf,
        })
    }
}

/// Incomplete or conflicting stateful browser-security configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatefulSecurityBuildError {
    /// Durable context persistence was omitted.
    MissingContextRepository,
    /// Session fixation protection was omitted.
    MissingSessionStrategy,
    /// Authentication-cookie policy was omitted.
    MissingSessionCookie,
    /// Cookie authentication did not explicitly enable or disable CSRF.
    MissingCsrfDecision,
    /// Authentication and CSRF cookies used the same exact name.
    CookieNameCollision,
}

impl fmt::Display for StatefulSecurityBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingContextRepository => "stateful security requires a context repository",
            Self::MissingSessionStrategy => "stateful security requires a session strategy",
            Self::MissingSessionCookie => "stateful security requires a session cookie",
            Self::MissingCsrfDecision => "stateful security requires an explicit CSRF decision",
            Self::CookieNameCollision => "session and CSRF cookie names must differ",
        })
    }
}

impl Error for StatefulSecurityBuildError {}

/// Application response instruction consumed by the stateful security chain.
///
/// Return this as an Axum response extension from a body-authentication route.
/// Butter removes it before the response leaves the security boundary and
/// performs persistence before emitting cookies.
#[derive(Clone)]
pub struct SessionTransition {
    pub(crate) kind: SessionTransitionKind,
}

impl SessionTransition {
    /// Establishes or elevates a session with a credential-free result.
    #[must_use]
    pub fn establish(authentication: Authentication) -> Self {
        Self {
            kind: SessionTransitionKind::Establish(authentication.into_context()),
        }
    }

    /// Rotates the current authenticated session and its CSRF token.
    #[must_use]
    pub const fn refresh() -> Self {
        Self {
            kind: SessionTransitionKind::Refresh,
        }
    }

    /// Re-exposes the stored CSRF token without rewriting session state.
    ///
    /// Use this on an authenticated safe-method endpoint when an SPA needs to
    /// recover its script-readable CSRF cookie after application startup.
    #[must_use]
    pub const fn expose_csrf() -> Self {
        Self {
            kind: SessionTransitionKind::ExposeCsrf,
        }
    }

    /// Invalidates server state and then expires browser cookies.
    #[must_use]
    pub const fn logout() -> Self {
        Self {
            kind: SessionTransitionKind::Logout,
        }
    }
}

impl fmt::Debug for SessionTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            SessionTransitionKind::Establish(_) => "SessionTransition::Establish([REDACTED])",
            SessionTransitionKind::Refresh => "SessionTransition::Refresh",
            SessionTransitionKind::ExposeCsrf => "SessionTransition::ExposeCsrf",
            SessionTransitionKind::Logout => "SessionTransition::Logout",
        })
    }
}

#[derive(Clone)]
pub(crate) enum SessionTransitionKind {
    Establish(SecurityContext),
    Refresh,
    ExposeCsrf,
    Logout,
}

pub(crate) fn secret_values_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use butter_web::browser::{BrowserOrigin, CookieName, SameSite};

    #[test]
    fn identifiers_are_bounded_and_redacted() {
        let identifier = SessionIdentifier::new("private-session").expect("identifier");
        assert!(!format!("{identifier:?}").contains("private-session"));
        assert!(SessionIdentifier::new("").is_err());
        assert!(SessionIdentifier::new("x".repeat(MAX_SESSION_IDENTIFIER_BYTES + 1)).is_err());
    }

    #[test]
    fn session_cookie_requires_http_only() {
        let origin = BrowserOrigin::loopback_http("http://localhost:3000").expect("origin");
        let cookie = BrowserCookie::new(
            &origin,
            CookieName::new("session").expect("name"),
            SameSite::Lax,
            CookieVisibility::ScriptReadable,
        )
        .expect("cookie");
        assert!(matches!(
            SessionCookie::new(
                cookie,
                CookieLifetime::Session,
                CookieHeaderPolicy::TargetOnly
            ),
            Err(SessionConfigurationError::SessionCookieMustBeHttpOnly)
        ));
    }

    #[test]
    fn secret_comparison_handles_different_lengths() {
        assert!(secret_values_equal("same", "same"));
        assert!(!secret_values_equal("same", "different"));
        assert!(!secret_values_equal("same", "same-more"));
    }
}
