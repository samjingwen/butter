use crate::RequestMetadata;
use butter_security::{AuthenticationFailure, AuthorizationFailure};
use butter_web::native::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use std::{future::Future, pin::Pin};

/// Web authentication failure presented to an entry point without credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebAuthenticationFailure {
    /// Authorization required credentials, but the request remained anonymous.
    MissingCredentials,
    /// Credential presentation was malformed, conflicting or oversized.
    Extraction(crate::CredentialExtractionFailure),
    /// A configured authentication manager failed.
    Authentication(AuthenticationFailure),
}

/// Boxed response future used by security failure handlers.
pub type SecurityResponseFuture<'a> = Pin<Box<dyn Future<Output = Response<Body>> + Send + 'a>>;

/// Maps authentication failure to an HTTP response.
pub trait AuthenticationEntryPoint: Send + Sync {
    /// Produces a bounded response without receiving credential material.
    fn commence<'a>(
        &'a self,
        request: &'a RequestMetadata,
        failure: WebAuthenticationFailure,
    ) -> SecurityResponseFuture<'a>;
}

/// Maps authorization failure to an HTTP response.
pub trait AccessDeniedHandler: Send + Sync {
    /// Produces a bounded response without receiving credential material.
    fn denied<'a>(
        &'a self,
        request: &'a RequestMetadata,
        failure: AuthorizationFailure,
    ) -> SecurityResponseFuture<'a>;
}

/// Empty, cache-resistant authentication responses with an optional challenge.
#[derive(Clone, Default)]
pub struct NeutralAuthenticationEntryPoint {
    challenge: Option<HeaderValue>,
}

impl NeutralAuthenticationEntryPoint {
    /// Creates neutral responses without a `WWW-Authenticate` challenge.
    #[must_use]
    pub const fn new() -> Self {
        Self { challenge: None }
    }

    /// Creates neutral responses with a validated challenge header value.
    #[must_use]
    pub const fn with_challenge(challenge: HeaderValue) -> Self {
        Self {
            challenge: Some(challenge),
        }
    }

    /// Creates a neutral `Bearer` challenge.
    #[must_use]
    pub fn bearer() -> Self {
        Self::with_challenge(HeaderValue::from_static("Bearer"))
    }
}

impl AuthenticationEntryPoint for NeutralAuthenticationEntryPoint {
    fn commence<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        failure: WebAuthenticationFailure,
    ) -> SecurityResponseFuture<'a> {
        Box::pin(async move {
            let status = match failure {
                WebAuthenticationFailure::MissingCredentials
                | WebAuthenticationFailure::Authentication(
                    AuthenticationFailure::Rejected(_)
                    | AuthenticationFailure::UnsupportedMechanism,
                ) => StatusCode::UNAUTHORIZED,
                WebAuthenticationFailure::Extraction(_) => StatusCode::BAD_REQUEST,
                WebAuthenticationFailure::Authentication(AuthenticationFailure::Operational(_)) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
            };
            let mut response = empty_response(status);
            if status == StatusCode::UNAUTHORIZED
                && let Some(challenge) = &self.challenge
            {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, challenge.clone());
            }
            response
        })
    }
}

/// Empty, cache-resistant authorization responses.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeutralAccessDeniedHandler;

impl AccessDeniedHandler for NeutralAccessDeniedHandler {
    fn denied<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        failure: AuthorizationFailure,
    ) -> SecurityResponseFuture<'a> {
        Box::pin(async move {
            empty_response(match failure {
                AuthorizationFailure::Denied | AuthorizationFailure::NoGrant => {
                    StatusCode::FORBIDDEN
                }
                AuthorizationFailure::Operational(_) => StatusCode::SERVICE_UNAVAILABLE,
            })
        })
    }
}

pub(crate) fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
