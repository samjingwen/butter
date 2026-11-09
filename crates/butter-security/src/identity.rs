use std::{any::Any, error::Error, fmt, sync::Arc};

const MAX_SUBJECT_BYTES: usize = 256;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_AUTHORITY_BYTES: usize = 128;

/// Sanitized validation failure for a non-secret identity value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// A stable subject identifier was empty, too long or contained control data.
    InvalidSubject,
    /// A display name was empty, too long or contained control data.
    InvalidDisplayName,
    /// An authority was empty, too long or contained control data.
    InvalidAuthority,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSubject => "invalid security subject identifier",
            Self::InvalidDisplayName => "invalid security display name",
            Self::InvalidAuthority => "invalid security authority",
        })
    }
}

impl Error for IdentityError {}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

/// Stable, non-secret identity of an authenticated principal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubjectId(Arc<str>);

impl SubjectId {
    /// Validates and owns a subject identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAX_SUBJECT_BYTES) {
            return Err(IdentityError::InvalidSubject);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the stable subject identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Non-authoritative name intended only for display and diagnostics.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DisplayName(Arc<str>);

impl DisplayName {
    /// Validates and owns a display name.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAX_DISPLAY_NAME_BYTES) {
            return Err(IdentityError::InvalidDisplayName);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the display name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact, case-sensitive application authority with no implicit prefix.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Authority(Arc<str>);

impl Authority {
    /// Validates and owns an authority.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAX_AUTHORITY_BYTES) {
            return Err(IdentityError::InvalidAuthority);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the exact authority.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Application-defined, non-secret authenticated identity.
///
/// Domain data can be recovered with [`Principal::as_any`] and `Any`
/// downcasting. Implementations must be immutable after construction and must
/// not contain or return credentials.
///
/// ```
/// use butter_security::{DisplayName, Principal, SubjectId};
/// use std::any::Any;
///
/// struct AccountPrincipal {
///     subject: SubjectId,
///     name: DisplayName,
/// }
///
/// impl Principal for AccountPrincipal {
///     fn subject(&self) -> &SubjectId { &self.subject }
///     fn display_name(&self) -> Option<&DisplayName> { Some(&self.name) }
///     fn as_any(&self) -> &dyn Any { self }
/// }
/// ```
pub trait Principal: Any + Send + Sync {
    /// Returns the stable identifier used to correlate this principal.
    fn subject(&self) -> &SubjectId;

    /// Returns an optional non-authoritative display name.
    fn display_name(&self) -> Option<&DisplayName>;

    /// Exposes the concrete non-secret principal for typed downcasting.
    fn as_any(&self) -> &dyn Any;
}

impl dyn Principal {
    /// Attempts to recover an application principal's concrete type.
    #[must_use]
    pub fn downcast_ref<P: Principal>(&self) -> Option<&P> {
        self.as_any().downcast_ref()
    }
}

/// Basic principal suitable when no additional domain identity is required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedPrincipal {
    subject: SubjectId,
    display_name: Option<DisplayName>,
}

impl NamedPrincipal {
    /// Creates a principal from a stable subject and optional display name.
    #[must_use]
    pub fn new(subject: SubjectId, display_name: Option<DisplayName>) -> Self {
        Self {
            subject,
            display_name,
        }
    }
}

impl Principal for NamedPrincipal {
    fn subject(&self) -> &SubjectId {
        &self.subject
    }

    fn display_name(&self) -> Option<&DisplayName> {
        self.display_name.as_ref()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
