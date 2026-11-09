use crate::{Assurance, Authentication, Authority, Principal};
use std::fmt;

/// Immutable authenticated or anonymous state for exactly one request.
///
/// Butter does not store this value globally. A transport adapter is expected
/// to attach a clone to its own request-local extension storage.
#[derive(Clone, Default)]
pub struct SecurityContext {
    authentication: Option<Authentication>,
}

impl SecurityContext {
    /// Creates an anonymous context.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            authentication: None,
        }
    }

    /// Creates a context from a credential-free authenticated result.
    #[must_use]
    pub const fn authenticated(authentication: Authentication) -> Self {
        Self {
            authentication: Some(authentication),
        }
    }

    /// Reports whether this context contains successful authentication.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.authentication.is_some()
    }

    /// Returns the complete credential-free authentication when present.
    #[must_use]
    pub fn authentication(&self) -> Option<&Authentication> {
        self.authentication.as_ref()
    }

    /// Returns the authenticated principal when present.
    #[must_use]
    pub fn principal(&self) -> Option<&dyn Principal> {
        self.authentication.as_ref().map(Authentication::principal)
    }

    /// Returns the authenticated assurance when present.
    #[must_use]
    pub fn assurance(&self) -> Option<Assurance> {
        self.authentication.as_ref().map(Authentication::assurance)
    }

    /// Reports whether an authenticated result contains the exact authority.
    #[must_use]
    pub fn has_authority(&self, authority: &Authority) -> bool {
        self.authentication
            .as_ref()
            .is_some_and(|authentication| authentication.has_authority(authority))
    }
}

impl fmt::Debug for SecurityContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecurityContext")
            .field("authentication", &self.authentication)
            .finish()
    }
}
