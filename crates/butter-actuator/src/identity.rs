use std::{error::Error, fmt};

/// Sanitized inert construction failure, never containing rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// Names require 1-96 ASCII alphanumeric, dot, underscore or hyphen bytes.
    InvalidIdentity,
    /// Contributor identities must be unique within an Actuator.
    DuplicateContributor,
    /// At most 64 contributors may participate in one Actuator.
    ContributorLimit,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "invalid Actuator identity",
            Self::DuplicateContributor => "duplicate Actuator contributor",
            Self::ContributorLimit => "Actuator contributor limit exceeded",
        })
    }
}
impl Error for BuildError {}

macro_rules! identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub struct $name(&'static str);
        impl $name {
            /// Validate a bounded static safe name without retaining rejected input.
            pub fn new(value: &'static str) -> Result<Self, BuildError> {
                if value.is_empty()
                    || value.len() > 96
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                {
                    return Err(BuildError::InvalidIdentity);
                }
                Ok(Self(value))
            }
            /// The validated local identity, not an HTTP path or arbitrary label.
            pub const fn as_str(self) -> &'static str {
                self.0
            }
        }
    };
}
identity!(
    ContributorId,
    "Validated, stable local contributor and supervisor component identity."
);
identity!(
    EndpointId,
    "Validated transport-independent endpoint identity."
);

impl EndpointId {
    /// The only built-in endpoint in this experimental slice.
    pub const HEALTH: Self = Self("health");
}
