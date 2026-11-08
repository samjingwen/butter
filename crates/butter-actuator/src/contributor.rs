use butter_core::health::{HealthReader, HealthSnapshot};
use std::{
    fmt,
    sync::{Arc, Mutex},
};

/// Trusted local diagnostics, never passed to an endpoint or HTTP renderer.
///
/// The latest concrete failure is retained even after recovery, timeout or stop.
/// It is historical, not necessarily the cause of the current snapshot, and is
/// read separately from that snapshot. Only this explicit capability can clone it.
pub struct ContributorDiagnostics<E> {
    reader: HealthReader<()>,
    failures: Arc<Mutex<Option<Arc<E>>>>,
}

impl<E> ContributorDiagnostics<E> {
    pub(crate) fn new(reader: HealthReader<()>, failures: Arc<Mutex<Option<Arc<E>>>>) -> Self {
        Self { reader, failures }
    }

    /// Fresh sanitized core snapshot; contains no application error value.
    pub fn snapshot(&self) -> HealthSnapshot<()> {
        self.reader.snapshot()
    }

    /// Deliberately clone the latest retained concrete failure for trusted inspection.
    /// Nothing in Butter automatically formats, logs or serializes this cause.
    pub fn last_failure(&self) -> Option<Arc<E>> {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl<E> Clone for ContributorDiagnostics<E> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            failures: self.failures.clone(),
        }
    }
}

impl<E> fmt::Debug for ContributorDiagnostics<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContributorDiagnostics")
            .field("snapshot", &self.reader.snapshot())
            .field("failure", &"redacted")
            .finish()
    }
}
