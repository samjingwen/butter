use crate::{RequestMatcher, RequestMetadata, SessionIdentifier, session::secret_values_equal};
use butter_web::{
    browser::{
        BrowserCookie, BrowserOrigin, CookieLifetime, CookieValue, CookieVisibility, SetCookieError,
    },
    native::{
        body::Body,
        http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header},
        response::Response,
    },
};
use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc};
use zeroize::Zeroize;

const MAX_CSRF_TOKEN_BYTES: usize = 1_024;
const MAX_ALLOWED_ORIGINS: usize = 64;

/// Redacting, zeroizing CSRF bearer token.
pub struct CsrfToken(String);

impl CsrfToken {
    /// Validates a non-empty cookie-safe token no larger than 1 KiB.
    pub fn new(value: impl Into<String>) -> Result<Self, CsrfTokenError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CSRF_TOKEN_BYTES {
            return Err(CsrfTokenError);
        }
        CookieValue::new(&value).map_err(|_| CsrfTokenError)?;
        Ok(Self(value))
    }

    /// Deliberately exposes the token to its repository or request handler.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    fn cookie_value(&self) -> CookieValue<'_> {
        CookieValue::new(&self.0).expect("validated CSRF token remains valid")
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CsrfToken([REDACTED])")
    }
}

impl Zeroize for CsrfToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for CsrfToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Sanitized invalid-CSRF-token error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CsrfTokenError;

impl fmt::Display for CsrfTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid CSRF token")
    }
}

impl Error for CsrfTokenError {}

/// Result of loading the expected token for one session.
#[derive(Debug)]
pub enum CsrfTokenLoad {
    /// The session currently has no usable CSRF token.
    Missing,
    /// The expected token was loaded.
    Found(CsrfToken),
}

/// Sanitized CSRF storage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsrfOperationError {
    /// A required durable dependency was unavailable.
    Unavailable,
    /// The operation exceeded an application-owned deadline.
    TimedOut,
    /// Persistence may or may not have committed and must not be replayed blindly.
    Unconfirmed,
    /// Another internal CSRF operation failed.
    Internal,
}

impl fmt::Display for CsrfOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "CSRF dependency unavailable",
            Self::TimedOut => "CSRF operation timed out",
            Self::Unconfirmed => "CSRF persistence outcome is unconfirmed",
            Self::Internal => "CSRF operation failed",
        })
    }
}

impl Error for CsrfOperationError {}

/// Boxed CSRF-token load future.
pub type CsrfTokenLoadFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CsrfTokenLoad, CsrfOperationError>> + Send + 'a>>;

/// Boxed CSRF-token creation or rotation future.
pub type CsrfTokenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CsrfToken, CsrfOperationError>> + Send + 'a>>;

/// Boxed CSRF-token invalidation future.
pub type CsrfWriteFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), CsrfOperationError>> + Send + 'a>>;

/// Application-owned CSRF token storage and generation.
///
/// Implementations generate unpredictable bearer values. `rotate` receives the
/// old and new session identifiers so durable stores can replace the token
/// atomically with session rotation. `Unconfirmed` does not prove a write
/// failed, and Butter does not automatically replay it.
pub trait CsrfTokenRepository: Send + Sync {
    /// Loads the expected token without creating or refreshing one.
    fn load<'a>(
        &'a self,
        request: &'a RequestMetadata,
        session: &'a SessionIdentifier,
    ) -> CsrfTokenLoadFuture<'a>;

    /// Creates the first token for a newly established session.
    fn create<'a>(
        &'a self,
        request: &'a RequestMetadata,
        session: &'a SessionIdentifier,
    ) -> CsrfTokenFuture<'a>;

    /// Replaces the token while a session identifier is rotated.
    fn rotate<'a>(
        &'a self,
        request: &'a RequestMetadata,
        previous: &'a SessionIdentifier,
        session: &'a SessionIdentifier,
    ) -> CsrfTokenFuture<'a>;

    /// Invalidates the token during logout or explicit session invalidation.
    fn invalidate<'a>(
        &'a self,
        request: &'a RequestMetadata,
        session: &'a SessionIdentifier,
    ) -> CsrfWriteFuture<'a>;
}

/// Sanitized presented-token parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsrfPresentationError {
    /// The configured header was repeated, malformed, empty, or oversized.
    Malformed,
}

impl fmt::Display for CsrfPresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CSRF token presentation failed")
    }
}

impl Error for CsrfPresentationError {}

/// Sanitized CSRF response-cookie failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsrfResponseError {
    /// A same-name response cookie already existed or serialization failed.
    Cookie,
}

impl fmt::Display for CsrfResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CSRF response cookie failed")
    }
}

impl Error for CsrfResponseError {}

impl From<SetCookieError> for CsrfResponseError {
    fn from(_: SetCookieError) -> Self {
        Self::Cookie
    }
}

/// HTTP presentation contract for CSRF tokens.
///
/// The handler resolves one submitted token and controls browser exposure. It
/// reports its exact cookie name so stateful construction can reject collision
/// with the authentication cookie.
pub trait CsrfTokenRequestHandler: Send + Sync {
    /// Resolves at most one presented token from request headers.
    fn resolve(&self, headers: &HeaderMap) -> Result<Option<CsrfToken>, CsrfPresentationError>;

    /// Appends the browser-visible token representation after persistence.
    fn expose(&self, headers: &mut HeaderMap, token: &CsrfToken) -> Result<(), CsrfResponseError>;

    /// Appends a matching browser-side removal after invalidation.
    fn remove(&self, headers: &mut HeaderMap) -> Result<(), CsrfResponseError>;

    /// Returns the exact CSRF cookie name used by this handler.
    fn cookie_name(&self) -> &butter_web::browser::CookieName;
}

/// Cookie-and-header CSRF presentation suitable for browser SPAs.
///
/// Configure the header and cookie names in the SPA client. Angular's standard
/// `X-XSRF-TOKEN` header is supported, while secure deployments can use a
/// stronger `__Host-` cookie name required by the upstream cookie policy. Only
/// this CSRF cookie is script-readable; the session cookie remains `HttpOnly`.
#[derive(Clone, Debug)]
pub struct SpaCsrfTokenRequestHandler {
    header_name: HeaderName,
    cookie: BrowserCookie,
    lifetime: CookieLifetime,
}

impl SpaCsrfTokenRequestHandler {
    /// Creates a bounded header/cookie presentation policy.
    pub fn new(
        header_name: HeaderName,
        cookie: BrowserCookie,
        lifetime: CookieLifetime,
    ) -> Result<Self, CsrfHandlerConfigurationError> {
        if cookie.visibility() != CookieVisibility::ScriptReadable {
            return Err(CsrfHandlerConfigurationError::CookieMustBeScriptReadable);
        }
        if is_browser_controlled_header(&header_name) {
            return Err(CsrfHandlerConfigurationError::InvalidHeaderName);
        }
        Ok(Self {
            header_name,
            cookie,
            lifetime,
        })
    }

    /// Returns the configured submitted-token header name.
    #[must_use]
    pub const fn header_name(&self) -> &HeaderName {
        &self.header_name
    }

    /// Returns the script-readable CSRF cookie policy.
    #[must_use]
    pub const fn cookie(&self) -> &BrowserCookie {
        &self.cookie
    }
}

impl CsrfTokenRequestHandler for SpaCsrfTokenRequestHandler {
    fn resolve(&self, headers: &HeaderMap) -> Result<Option<CsrfToken>, CsrfPresentationError> {
        let mut values = headers.get_all(&self.header_name).iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(CsrfPresentationError::Malformed);
        }
        let value = value
            .to_str()
            .map_err(|_| CsrfPresentationError::Malformed)?;
        CsrfToken::new(value.to_owned())
            .map(Some)
            .map_err(|_| CsrfPresentationError::Malformed)
    }

    fn expose(&self, headers: &mut HeaderMap, token: &CsrfToken) -> Result<(), CsrfResponseError> {
        self.cookie
            .append(headers, token.cookie_value(), self.lifetime)
            .map_err(Into::into)
    }

    fn remove(&self, headers: &mut HeaderMap) -> Result<(), CsrfResponseError> {
        self.cookie.append_removal(headers).map_err(Into::into)
    }

    fn cookie_name(&self) -> &butter_web::browser::CookieName {
        self.cookie.name()
    }
}

fn is_browser_controlled_header(name: &HeaderName) -> bool {
    name == header::COOKIE
        || name == header::HOST
        || name == header::ORIGIN
        || name == header::REFERER
        || name == header::CONTENT_LENGTH
        || name.as_str().starts_with("sec-")
        || name.as_str().starts_with("proxy-")
}

/// Invalid SPA CSRF handler configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsrfHandlerConfigurationError {
    /// CSRF cookie exposure requires deliberate script readability.
    CookieMustBeScriptReadable,
    /// The submitted-token header is controlled by the browser.
    InvalidHeaderName,
}

impl fmt::Display for CsrfHandlerConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CookieMustBeScriptReadable => "SPA CSRF cookie must be script-readable",
            Self::InvalidHeaderName => "invalid SPA CSRF request header name",
        })
    }
}

impl Error for CsrfHandlerConfigurationError {}

/// Whether an absent `Origin` may fall back to a validated `Referer` origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefererFallback {
    /// Require `Origin`; do not inspect `Referer`.
    Disabled,
    /// Accept one absolute `Referer` whose origin is allow-listed.
    Enabled,
}

/// Exact trusted-origin policy for unsafe browser requests.
#[derive(Clone, Debug)]
pub struct OriginPolicy {
    allowed: Vec<BrowserOrigin>,
    referer_fallback: RefererFallback,
}

impl OriginPolicy {
    /// Creates a bounded non-empty exact-origin allow-list.
    pub fn new(
        allowed: Vec<BrowserOrigin>,
        referer_fallback: RefererFallback,
    ) -> Result<Self, OriginPolicyError> {
        if allowed.is_empty() {
            return Err(OriginPolicyError::NoOrigins);
        }
        if allowed.len() > MAX_ALLOWED_ORIGINS {
            return Err(OriginPolicyError::OriginLimit);
        }
        if allowed
            .iter()
            .enumerate()
            .any(|(index, origin)| allowed[index + 1..].iter().any(|other| origin == other))
        {
            return Err(OriginPolicyError::DuplicateOrigin);
        }
        Ok(Self {
            allowed,
            referer_fallback,
        })
    }

    /// Returns trusted origins in matching order.
    pub fn allowed_origins(&self) -> impl ExactSizeIterator<Item = &BrowserOrigin> {
        self.allowed.iter()
    }

    /// Returns the explicit fallback decision.
    #[must_use]
    pub const fn referer_fallback(&self) -> RefererFallback {
        self.referer_fallback
    }

    pub(crate) fn check(&self, headers: &HeaderMap) -> Result<(), OriginRejection> {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        if let Some(origin) = origins.next() {
            if origins.next().is_some() {
                return Err(OriginRejection::Ambiguous);
            }
            let origin = origin.to_str().map_err(|_| OriginRejection::Ambiguous)?;
            return self
                .allowed
                .iter()
                .any(|allowed| allowed.as_str() == origin)
                .then_some(())
                .ok_or(OriginRejection::Mismatch);
        }
        if self.referer_fallback == RefererFallback::Disabled {
            return Err(OriginRejection::Missing);
        }
        let mut referers = headers.get_all(header::REFERER).iter();
        let referer = referers.next().ok_or(OriginRejection::Missing)?;
        if referers.next().is_some() {
            return Err(OriginRejection::Ambiguous);
        }
        let referer = referer.to_str().map_err(|_| OriginRejection::Ambiguous)?;
        let uri: Uri = referer.parse().map_err(|_| OriginRejection::Mismatch)?;
        let scheme = uri.scheme_str().ok_or(OriginRejection::Mismatch)?;
        let authority = uri.authority().ok_or(OriginRejection::Mismatch)?;
        let candidate = format!("{scheme}://{authority}");
        self.allowed
            .iter()
            .any(|allowed| allowed.as_str() == candidate)
            .then_some(())
            .ok_or(OriginRejection::Mismatch)
    }
}

/// Invalid trusted-origin policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginPolicyError {
    /// At least one trusted origin is required.
    NoOrigins,
    /// More than 64 trusted origins were configured.
    OriginLimit,
    /// The exact same canonical origin was repeated.
    DuplicateOrigin,
}

impl fmt::Display for OriginPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoOrigins => "origin policy requires a trusted origin",
            Self::OriginLimit => "trusted origin limit exceeded",
            Self::DuplicateOrigin => "trusted origin is duplicated",
        })
    }
}

impl Error for OriginPolicyError {}

/// Sanitized unsafe-request origin rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginRejection {
    /// Neither `Origin` nor an enabled fallback was present.
    Missing,
    /// The selected field was repeated or malformed.
    Ambiguous,
    /// The presented origin was not allow-listed.
    Mismatch,
}

/// Standard matcher for methods that are not safe and idempotent reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnsafeMethodMatcher;

impl RequestMatcher for UnsafeMethodMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        !matches!(
            request.method(),
            &Method::GET | &Method::HEAD | &Method::OPTIONS | &Method::TRACE
        )
    }
}

/// Exploit-protection failure passed to the configured denial handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExploitProtectionFailure {
    /// Unsafe-request origin validation failed.
    Origin(OriginRejection),
    /// The submitted CSRF token was absent, malformed, unknown, or unequal.
    Csrf,
}

/// Boxed exploit-protection denial response future.
pub type ExploitProtectionResponseFuture<'a> =
    Pin<Box<dyn Future<Output = Response<Body>> + Send + 'a>>;

/// Maps origin or CSRF rejection to an HTTP response.
pub trait ExploitProtectionDeniedHandler: Send + Sync {
    /// Produces a bounded response without receiving token values.
    fn denied<'a>(
        &'a self,
        request: &'a RequestMetadata,
        failure: ExploitProtectionFailure,
    ) -> ExploitProtectionResponseFuture<'a>;
}

/// Empty, cache-resistant exploit-protection denial response.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeutralExploitProtectionDeniedHandler;

impl ExploitProtectionDeniedHandler for NeutralExploitProtectionDeniedHandler {
    fn denied<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        _failure: ExploitProtectionFailure,
    ) -> ExploitProtectionResponseFuture<'a> {
        Box::pin(async { crate::response::empty_response(StatusCode::FORBIDDEN) })
    }
}

/// Complete CSRF and origin enforcement for one stateful chain.
pub struct CsrfProtection {
    pub(crate) repository: Arc<dyn CsrfTokenRepository>,
    pub(crate) request_handler: Arc<dyn CsrfTokenRequestHandler>,
    pub(crate) unsafe_matcher: Arc<dyn RequestMatcher>,
    pub(crate) origin_policy: OriginPolicy,
    pub(crate) denied_handler: Arc<dyn ExploitProtectionDeniedHandler>,
}

impl CsrfProtection {
    /// Starts explicit CSRF construction.
    #[must_use]
    pub fn builder() -> CsrfProtectionBuilder {
        CsrfProtectionBuilder::default()
    }
}

/// Explicit builder for CSRF and origin enforcement.
#[derive(Default)]
pub struct CsrfProtectionBuilder {
    repository: Option<Arc<dyn CsrfTokenRepository>>,
    request_handler: Option<Arc<dyn CsrfTokenRequestHandler>>,
    unsafe_matcher: Option<Arc<dyn RequestMatcher>>,
    origin_policy: Option<OriginPolicy>,
    denied_handler: Option<Arc<dyn ExploitProtectionDeniedHandler>>,
}

impl CsrfProtectionBuilder {
    /// Installs durable expected-token storage and generation.
    pub fn token_repository(&mut self, repository: Arc<dyn CsrfTokenRepository>) -> &mut Self {
        self.repository = Some(repository);
        self
    }

    /// Installs request resolution and response exposure.
    pub fn request_handler(&mut self, handler: Arc<dyn CsrfTokenRequestHandler>) -> &mut Self {
        self.request_handler = Some(handler);
        self
    }

    /// Selects which normalized requests require exploit protection.
    pub fn unsafe_request_matcher(&mut self, matcher: Arc<dyn RequestMatcher>) -> &mut Self {
        self.unsafe_matcher = Some(matcher);
        self
    }

    /// Installs the trusted browser-origin allow-list.
    pub fn origin_policy(&mut self, policy: OriginPolicy) -> &mut Self {
        self.origin_policy = Some(policy);
        self
    }

    /// Installs origin and token rejection translation.
    pub fn denied_handler(
        &mut self,
        handler: Arc<dyn ExploitProtectionDeniedHandler>,
    ) -> &mut Self {
        self.denied_handler = Some(handler);
        self
    }

    /// Installs standard unsafe methods and a neutral `403` denial response.
    pub fn standard_request_protection(&mut self) -> &mut Self {
        self.unsafe_request_matcher(Arc::new(UnsafeMethodMatcher));
        self.denied_handler(Arc::new(NeutralExploitProtectionDeniedHandler));
        self
    }

    /// Validates and completes CSRF protection.
    pub fn build(self) -> Result<CsrfProtection, CsrfBuildError> {
        Ok(CsrfProtection {
            repository: self.repository.ok_or(CsrfBuildError::MissingRepository)?,
            request_handler: self
                .request_handler
                .ok_or(CsrfBuildError::MissingRequestHandler)?,
            unsafe_matcher: self
                .unsafe_matcher
                .ok_or(CsrfBuildError::MissingUnsafeMatcher)?,
            origin_policy: self
                .origin_policy
                .ok_or(CsrfBuildError::MissingOriginPolicy)?,
            denied_handler: self
                .denied_handler
                .ok_or(CsrfBuildError::MissingDeniedHandler)?,
        })
    }
}

/// Incomplete CSRF protection configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsrfBuildError {
    /// Expected-token storage was omitted.
    MissingRepository,
    /// Token presentation was omitted.
    MissingRequestHandler,
    /// Unsafe method selection was omitted.
    MissingUnsafeMatcher,
    /// Trusted-origin validation was omitted.
    MissingOriginPolicy,
    /// Denial translation was omitted.
    MissingDeniedHandler,
}

impl fmt::Display for CsrfBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingRepository => "CSRF protection requires a token repository",
            Self::MissingRequestHandler => "CSRF protection requires a request handler",
            Self::MissingUnsafeMatcher => "CSRF protection requires an unsafe-request matcher",
            Self::MissingOriginPolicy => "CSRF protection requires an origin policy",
            Self::MissingDeniedHandler => "CSRF protection requires a denial handler",
        })
    }
}

impl Error for CsrfBuildError {}

pub(crate) fn tokens_equal(expected: &CsrfToken, presented: &CsrfToken) -> bool {
    secret_values_equal(expected.expose_secret(), presented.expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use butter_web::{
        browser::{CookieName, SameSite},
        native::http::HeaderValue,
    };

    #[test]
    fn origin_policy_prefers_origin_and_uses_only_explicit_referer_fallback() {
        let trusted = BrowserOrigin::https("https://app.example").expect("origin");
        let strict =
            OriginPolicy::new(vec![trusted.clone()], RefererFallback::Disabled).expect("policy");
        let fallback = OriginPolicy::new(vec![trusted], RefererFallback::Enabled).expect("policy");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://app.example/account"),
        );
        assert_eq!(strict.check(&headers), Err(OriginRejection::Missing));
        assert_eq!(fallback.check(&headers), Ok(()));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://attacker.example"),
        );
        assert_eq!(fallback.check(&headers), Err(OriginRejection::Mismatch));
    }

    #[test]
    fn spa_handler_requires_script_readable_cookie_and_redacts_tokens() {
        let origin = BrowserOrigin::loopback_http("http://localhost:3000").expect("origin");
        let cookie = BrowserCookie::new(
            &origin,
            CookieName::new("XSRF-TOKEN").expect("name"),
            SameSite::Lax,
            CookieVisibility::ScriptReadable,
        )
        .expect("cookie");
        let handler = SpaCsrfTokenRequestHandler::new(
            HeaderName::from_static("x-xsrf-token"),
            cookie,
            CookieLifetime::Session,
        )
        .expect("handler");
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-xsrf-token"),
            HeaderValue::from_static("private-token"),
        );
        let token = handler.resolve(&headers).expect("resolve").expect("token");
        assert!(!format!("{token:?}").contains("private-token"));
    }
}
