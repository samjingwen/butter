//! Validated, first-match HTTP security composition for Butter applications.
//!
//! This crate is the only package that connects transport-independent
//! [`butter_security`] policy to [`butter_web`]. It wraps guarded application
//! routes before Butter assembles admission, deadlines, observation, Actuator
//! reads and graceful shutdown. Enabling a feature does not install a chain or
//! expose a route: an application must build and explicitly attach
//! [`SecurityWeb`]. `butter-boot` users attach it through
//! `Application::security`; custom bootstraps may call [`SecurityWeb::protect`]
//! only after route construction is complete.
//!
//! Request security uses immutable [`SecurityContext`] values stored only in
//! Axum request extensions. There is no thread-local or global current caller.
//! Stateful chains use application-supplied repositories and strategies; this
//! crate contains no hidden production session store, identity schema or token
//! generator. Body-authentication routes return [`SessionTransition`] as a
//! response extension, which Butter consumes before the response leaves the
//! boundary.
//! Dropping a request future drops the active authentication or authorization
//! or repository future, but does not prove that detached work stopped or that
//! an unconfirmed remote write rolled back. A successful durable write also
//! does not prove that the client received the response cookie.
//!
//! ```
//! use butter_security::AuthenticatedRequired;
//! use butter_security_web::{
//!     AnyRequest, SecurityChain, SecurityComponentId, SecurityWeb, UnmatchedPolicy,
//! };
//! use butter_web::{Router, routing::get};
//! use std::sync::Arc;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut chain = SecurityChain::builder(
//!     SecurityComponentId::new("application")?,
//!     100,
//!     Arc::new(AnyRequest),
//! );
//! chain.authorization_manager(Arc::new(AuthenticatedRequired));
//! chain.neutral_handlers();
//! let mut security = SecurityWeb::builder();
//! security.chain(chain.build()?)?;
//! security.unmatched_policy(UnmatchedPolicy::Deny);
//! let routes = security.build()?.protect(
//!     Router::new().route("/", get(|| async { "protected" })),
//! );
//! # let _ = routes;
//! # Ok(()) }
//! ```

mod chain;
mod csrf;
mod extraction;
mod matcher;
mod request;
mod response;
mod session;

pub use butter_security::SecurityContext;
pub use butter_web::browser::{
    BrowserCookie, BrowserOrigin, BrowserOriginError, CookieHeaderPolicy, CookieLifetime,
    CookieMaxAge, CookieName, CookieNameError, CookiePolicyError, CookieVisibility, SameSite,
};
pub use chain::{
    PIPELINE_STAGES, PipelineStage, SecurityBuildError, SecurityChain, SecurityChainBuilder,
    SecurityComponentId, SecurityWeb, SecurityWebBuilder, UnmatchedPolicy,
};
pub use csrf::{
    CsrfBuildError, CsrfHandlerConfigurationError, CsrfOperationError, CsrfPresentationError,
    CsrfProtection, CsrfProtectionBuilder, CsrfResponseError, CsrfToken, CsrfTokenError,
    CsrfTokenFuture, CsrfTokenLoad, CsrfTokenLoadFuture, CsrfTokenRepository,
    CsrfTokenRequestHandler, CsrfWriteFuture, ExploitProtectionDeniedHandler,
    ExploitProtectionFailure, ExploitProtectionResponseFuture,
    NeutralExploitProtectionDeniedHandler, OriginPolicy, OriginPolicyError, OriginRejection,
    RefererFallback, SpaCsrfTokenRequestHandler, UnsafeMethodMatcher,
};
pub use extraction::{
    BearerToken, BearerTokenExtractor, CredentialExtraction, CredentialExtractionFailure,
    CredentialExtractor, CredentialLimit, CredentialSource,
};
pub use matcher::{
    AllRequestMatcher, AnyRequest, AnyRequestMatcher, ExactPathMatcher, HeaderPresentMatcher,
    HostMatcher, MatcherBuildError, MatcherDescriptor, MethodMatcher, NotRequestMatcher,
    PathPrefixMatcher, RequestMatcher,
};
pub use request::{RequestIntegrityFailure, RequestMetadata};
pub use response::{
    AccessDeniedHandler, AuthenticationEntryPoint, NeutralAccessDeniedHandler,
    NeutralAuthenticationEntryPoint, SecurityResponseFuture, WebAuthenticationFailure,
};
pub use session::{
    SecurityContextLoad, SecurityContextLoadFuture, SecurityContextRepository,
    SessionAuthenticationStrategy, SessionConfigurationError, SessionCookie, SessionIdentifier,
    SessionIdentifierError, SessionOperationError, SessionRotationFuture, SessionTransition,
    SessionWriteFuture, StatefulSecurity, StatefulSecurityBuildError, StatefulSecurityBuilder,
};
