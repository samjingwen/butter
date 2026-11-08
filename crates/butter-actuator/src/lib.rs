//! Explicit, transport-independent health backed by supervised core monitors.
//!
//! Construction is inert. Register an [`Actuator`] inside protected startup;
//! only its [`RunningActuator`] can read live typed operations. Reads neither
//! probe dependencies nor renew observations. No result is a readiness lease.
//! Cancellation destroys probe futures, not necessarily remote or detached work.
//!
//! ```
//! use butter_actuator::{Actuator, ContributorGroup, ContributorId};
//! use butter_core::{health::HealthPolicy, startup::ProtectedStartupScope,
//!     lifecycle::LifecycleStatus};
//! use std::{convert::Infallible, time::Duration};
//! # fn register(scope: &mut ProtectedStartupScope, lifecycle: LifecycleStatus)
//! # -> Result<(), butter_core::BoxError> {
//! let second = Duration::from_secs(1);
//! let policy = HealthPolicy::new(second, second, second * 3, second)?;
//! let mut builder = Actuator::builder();
//! let diagnostics = builder.probe(ContributorId::new("store.health")?,
//!     ContributorGroup::Readiness, policy, || async { Ok::<_, Infallible>(()) })?;
//! let running = builder.build().register_in(scope, lifecycle)?;
//! let _status = running.health(butter_actuator::HealthView::Readiness);
//! # let _ = diagnostics;
//! # Ok(()) }
//! ```

mod contributor;
mod identity;

pub use contributor::ContributorDiagnostics;
pub use identity::{BuildError, ContributorId, EndpointId};

use butter_core::{
    RegistrationError,
    health::{HealthMonitor, HealthPolicy, HealthReader, HealthStatus},
    lifecycle::{LifecycleStatus, Readiness},
    registration::{Registration, RegistrationTarget},
};
use std::{fmt, future::Future, sync::Arc};

/// Explicit contributor membership. External liveness membership is unrepresentable.
///
/// ```compile_fail,E0599
/// use butter_actuator::ContributorGroup;
/// let forbidden = ContributorGroup::Liveness;
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContributorGroup {
    /// Participate only in overall health.
    Overall,
    /// Participate in overall health and readiness.
    Readiness,
}

/// Built-in typed health operation selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthView {
    /// Lifecycle readiness and every contributor.
    Overall,
    /// Process lifecycle only, never external dependencies.
    Liveness,
    /// Lifecycle readiness and explicitly selected contributors.
    Readiness,
}

/// The initial operation vocabulary has only read operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// Synchronous in-memory observation with no probe side effects.
    Read,
}

/// Metadata for one built-in operation, with no paths or HTTP policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthOperation {
    /// Stable endpoint identity.
    pub endpoint: EndpointId,
    /// Typed health view.
    pub view: HealthView,
    /// Operation semantics.
    pub kind: OperationKind,
}

/// Deterministic discovery of the three built-in health reads.
pub const HEALTH_OPERATIONS: [HealthOperation; 3] = [
    operation(HealthView::Overall),
    operation(HealthView::Liveness),
    operation(HealthView::Readiness),
];

const fn operation(view: HealthView) -> HealthOperation {
    HealthOperation {
        endpoint: EndpointId::HEALTH,
        view,
        kind: OperationKind::Read,
    }
}

/// Minimal sanitized status, without retained errors or transport policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// All required observations currently establish availability.
    Up,
    /// At least one required observation does not establish availability.
    Down,
}

/// A sanitized point-in-time operation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Health {
    /// Aggregate only; no names, errors, timestamps or configuration.
    pub status: Status,
}

type Register = dyn FnOnce(&mut Registration<'_>) -> Result<Contributor, RegistrationError> + Send;

struct Pending {
    id: ContributorId,
    register: Box<Register>,
}

/// Inert contributor plan. At most 64 contributors bound each aggregate read.
#[derive(Default)]
#[must_use = "build and register the plan to start its monitors"]
pub struct ActuatorBuilder {
    pending: Vec<Pending>,
}

impl ActuatorBuilder {
    /// Add a supervised probe, returning a trusted, concrete diagnostics capability.
    ///
    /// Names also identify supervisor components and must be unique there.
    /// This performs no I/O and invokes no probe. All acquisition must remain
    /// inside the returned future; factories, polls and destructors must not block.
    pub fn probe<F, Fut, E>(
        &mut self,
        id: ContributorId,
        group: ContributorGroup,
        policy: HealthPolicy,
        mut probe: F,
    ) -> Result<ContributorDiagnostics<E>, BuildError>
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: Send + Sync + 'static,
    {
        if self.pending.iter().any(|known| known.id == id) {
            return Err(BuildError::DuplicateContributor);
        }
        if self.pending.len() == 64 {
            return Err(BuildError::ContributorLimit);
        }
        let failures = Arc::new(std::sync::Mutex::new(None));
        let retained = failures.clone();
        // Never store application values in the reader used by endpoint reads:
        // even dropping a snapshot after concurrent replacement must not run E::drop.
        let monitor = HealthMonitor::new(policy, move || {
            let future = probe();
            let retained = retained.clone();
            async move {
                match future.await {
                    Ok(()) => Ok(()),
                    Err(cause) => {
                        let previous = retained
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .replace(Arc::new(cause));
                        drop(previous);
                        Err(())
                    }
                }
            }
        });
        let diagnostics = ContributorDiagnostics::new(monitor.reader(), failures);
        self.pending.push(Pending {
            id,
            register: Box::new(move |target| {
                let reader = monitor.register_in(target, id.as_str())?;
                Ok(Contributor { id, group, reader })
            }),
        });
        Ok(diagnostics)
    }

    /// Finish inert construction. No writer is started before registration.
    pub fn build(self) -> Actuator {
        Actuator {
            pending: self.pending,
        }
    }
}

/// Inert validated Actuator, consumed by protected registration.
#[must_use = "register the Actuator; an unattached plan starts no work"]
pub struct Actuator {
    pending: Vec<Pending>,
}

impl Actuator {
    /// Begin explicit contributor construction, with no automatic contributors.
    pub fn builder() -> ActuatorBuilder {
        ActuatorBuilder::default()
    }

    /// Transfer every writer into the existing supervisor and return read-only operations.
    /// Registration is inert until protected startup starts the components.
    /// On partial failure, protected startup must settle its registered components.
    pub fn register_in<T: RegistrationTarget + ?Sized>(
        self,
        target: &mut T,
        lifecycle: LifecycleStatus,
    ) -> Result<RunningActuator, RegistrationError> {
        let mut registration = target.registration();
        let contributors = self
            .pending
            .into_iter()
            .map(|pending| (pending.register)(&mut registration))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RunningActuator {
            contributors: contributors.into(),
            lifecycle,
        })
    }
}

struct Contributor {
    id: ContributorId,
    group: ContributorGroup,
    reader: HealthReader<()>,
}

/// Cloneable typed endpoint view. Cloning never retains a monitor writer.
#[derive(Clone)]
pub struct RunningActuator {
    contributors: Arc<[Contributor]>,
    lifecycle: LifecycleStatus,
}

impl RunningActuator {
    /// Read only published memory in deterministic order, then read lifecycle last.
    /// Liveness never reads contributors. This is not a multi-monitor transaction.
    pub fn health(&self, view: HealthView) -> Health {
        evaluate(
            view,
            self.contributors
                .iter()
                .filter(|contributor| {
                    view == HealthView::Overall || contributor.group == ContributorGroup::Readiness
                })
                .map(|contributor| contributor.reader.snapshot().status()),
            || self.lifecycle.readiness(),
        )
    }

    /// Registered safe identities in declaration order, for deliberate local inspection.
    pub fn contributor_ids(&self) -> impl ExactSizeIterator<Item = ContributorId> + '_ {
        self.contributors.iter().map(|contributor| contributor.id)
    }
}

fn evaluate(
    view: HealthView,
    observations: impl Iterator<Item = HealthStatus>,
    lifecycle: impl FnOnce() -> Readiness,
) -> Health {
    let mut healthy = true;
    if view != HealthView::Liveness {
        for status in observations {
            healthy &= status == HealthStatus::Healthy;
        }
    }
    // Lifecycle is deliberately last: an observed drain overrides prior successes.
    let lifecycle = lifecycle();
    let up = match view {
        HealthView::Liveness => lifecycle != Readiness::Stopped,
        HealthView::Overall | HealthView::Readiness => healthy && lifecycle == Readiness::Ready,
    };
    Health {
        status: if up { Status::Up } else { Status::Down },
    }
}

impl fmt::Debug for RunningActuator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunningActuator")
            .field("contributors", &self.contributors.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
