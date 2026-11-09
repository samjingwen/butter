use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Owned credential material that redacts formatting and zeroizes on drop.
///
/// Access requires an explicit call to [`Credential::expose_secret`]. The
/// wrapper intentionally implements neither `Clone` nor `Display`.
pub struct Credential<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Credential<T> {
    /// Wraps credential material for redacted ownership.
    pub fn new(secret: T) -> Self {
        Self(Zeroizing::new(secret))
    }

    /// Deliberately exposes the credential to the component that verifies it.
    #[must_use]
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> fmt::Debug for Credential<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential([REDACTED])")
    }
}
