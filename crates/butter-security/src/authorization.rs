use crate::{AssuranceLevel, Authority, SecurityContext};
use std::{
    collections::BTreeSet, error::Error, fmt, future::Future, marker::PhantomData, pin::Pin,
    sync::Arc,
};

const MAX_MANAGERS: usize = 64;
const MAX_AUTHORITIES: usize = 256;

/// Three-way policy decision before fail-closed enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// The policy explicitly allows the operation.
    Grant,
    /// The policy explicitly rejects the operation.
    Deny,
    /// The policy does not apply and therefore does not grant access.
    Abstain,
}

/// Sanitized operational failure from application authorization policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationOperationalError {
    /// Required policy data was unavailable.
    Unavailable,
    /// Policy evaluation exceeded an application-owned deadline.
    TimedOut,
    /// Policy evaluation failed for another internal reason.
    Internal,
}

impl fmt::Display for AuthorizationOperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "authorization dependency unavailable",
            Self::TimedOut => "authorization evaluation timed out",
            Self::Internal => "authorization evaluation failed",
        })
    }
}

impl Error for AuthorizationOperationalError {}

/// Fail-closed authorization result returned by [`authorize`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationFailure {
    /// A policy explicitly denied the operation.
    Denied,
    /// No policy explicitly granted the operation.
    NoGrant,
    /// Policy evaluation encountered an operational failure.
    Operational(AuthorizationOperationalError),
}

impl fmt::Display for AuthorizationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Denied => "authorization denied",
            Self::NoGrant => "authorization denied because no policy granted access",
            Self::Operational(_) => "authorization operation failed",
        })
    }
}

impl Error for AuthorizationFailure {}

/// Boxed authorization future used by heterogeneous policy composition.
pub type AuthorizationFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<AuthorizationDecision, AuthorizationOperationalError>>
            + Send
            + 'a,
    >,
>;

/// Asynchronous policy for one typed protected context.
///
/// A manager returns `Grant`, `Deny` or `Abstain`, with operational failures in
/// the outer `Result`. Callers enforce the decision through [`authorize`] so
/// abstention cannot become access. Dropping the future must release borrowed
/// context; detached policy work remains the implementation's responsibility.
///
/// ```
/// use butter_security::{
///     AuthorizationDecision, AuthorizationFuture, AuthorizationManager, SecurityContext,
/// };
///
/// struct PositiveOnly;
///
/// impl AuthorizationManager<i64> for PositiveOnly {
///     fn check<'a>(
///         &'a self,
///         _context: &'a SecurityContext,
///         value: &'a i64,
///     ) -> AuthorizationFuture<'a> {
///         Box::pin(async move {
///             Ok(if *value > 0 {
///                 AuthorizationDecision::Grant
///             } else {
///                 AuthorizationDecision::Deny
///             })
///         })
///     }
/// }
/// ```
pub trait AuthorizationManager<C: ?Sized + Sync>: Send + Sync {
    /// Evaluates this policy without converting abstention into access.
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        protected: &'a C,
    ) -> AuthorizationFuture<'a>;
}

/// Evaluates a policy and denies both explicit denial and all-abstain outcomes.
///
/// Dropping this future propagates cancellation by dropping the currently
/// evaluated manager future. Detached application work may continue.
pub async fn authorize<C: ?Sized + Sync>(
    manager: &(dyn AuthorizationManager<C> + '_),
    context: &SecurityContext,
    protected: &C,
) -> Result<(), AuthorizationFailure> {
    match manager
        .check(context, protected)
        .await
        .map_err(AuthorizationFailure::Operational)?
    {
        AuthorizationDecision::Grant => Ok(()),
        AuthorizationDecision::Deny => Err(AuthorizationFailure::Denied),
        AuthorizationDecision::Abstain => Err(AuthorizationFailure::NoGrant),
    }
}

fn ready(decision: AuthorizationDecision) -> AuthorizationFuture<'static> {
    Box::pin(async move { Ok(decision) })
}

/// Policy that explicitly grants every protected context.
#[derive(Clone, Copy, Debug, Default)]
pub struct PermitAll;

impl<C: ?Sized + Sync> AuthorizationManager<C> for PermitAll {
    fn check<'a>(
        &'a self,
        _context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(AuthorizationDecision::Grant)
    }
}

/// Policy that explicitly denies every protected context.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAll;

impl<C: ?Sized + Sync> AuthorizationManager<C> for DenyAll {
    fn check<'a>(
        &'a self,
        _context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(AuthorizationDecision::Deny)
    }
}

/// Policy requiring an authenticated context.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthenticatedRequired;

impl<C: ?Sized + Sync> AuthorizationManager<C> for AuthenticatedRequired {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(if context.is_authenticated() {
            AuthorizationDecision::Grant
        } else {
            AuthorizationDecision::Deny
        })
    }
}

/// Policy requiring an anonymous context.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnonymousRequired;

impl<C: ?Sized + Sync> AuthorizationManager<C> for AnonymousRequired {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(if context.is_authenticated() {
            AuthorizationDecision::Deny
        } else {
            AuthorizationDecision::Grant
        })
    }
}

/// Policy requiring one exact, case-sensitive authority.
#[derive(Clone, Debug)]
pub struct AuthorityRequired {
    authority: Authority,
}

impl AuthorityRequired {
    /// Creates an exact-authority policy.
    #[must_use]
    pub const fn new(authority: Authority) -> Self {
        Self { authority }
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for AuthorityRequired {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(if context.has_authority(&self.authority) {
            AuthorizationDecision::Grant
        } else {
            AuthorizationDecision::Deny
        })
    }
}

/// Sanitized construction failure for authorization composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationBuildError {
    /// A composite requires at least one manager.
    NoManagers,
    /// A composite accepts at most 64 managers.
    ManagerLimit,
    /// An authority-set policy requires at least one authority.
    NoAuthorities,
    /// An authority-set policy accepts at most 256 authority entries.
    AuthorityLimit,
}

impl fmt::Display for AuthorizationBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoManagers => "authorization composite requires a manager",
            Self::ManagerLimit => "authorization manager limit exceeded",
            Self::NoAuthorities => "authorization policy requires an authority",
            Self::AuthorityLimit => "authorization authority limit exceeded",
        })
    }
}

impl Error for AuthorizationBuildError {}

fn authority_set(
    authorities: impl IntoIterator<Item = Authority>,
) -> Result<BTreeSet<Authority>, AuthorizationBuildError> {
    let mut bounded = BTreeSet::new();
    for (index, authority) in authorities.into_iter().enumerate() {
        if index == MAX_AUTHORITIES {
            return Err(AuthorizationBuildError::AuthorityLimit);
        }
        bounded.insert(authority);
    }
    if bounded.is_empty() {
        return Err(AuthorizationBuildError::NoAuthorities);
    }
    Ok(bounded)
}

/// Policy requiring at least one authority from a non-empty set.
#[derive(Clone, Debug)]
pub struct AnyAuthorityRequired {
    authorities: BTreeSet<Authority>,
}

impl AnyAuthorityRequired {
    /// Creates a bounded any-authority policy.
    pub fn new(
        authorities: impl IntoIterator<Item = Authority>,
    ) -> Result<Self, AuthorizationBuildError> {
        Ok(Self {
            authorities: authority_set(authorities)?,
        })
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for AnyAuthorityRequired {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(
            if self
                .authorities
                .iter()
                .any(|authority| context.has_authority(authority))
            {
                AuthorizationDecision::Grant
            } else {
                AuthorizationDecision::Deny
            },
        )
    }
}

/// Policy requiring every authority in a non-empty set.
#[derive(Clone, Debug)]
pub struct AllAuthoritiesRequired {
    authorities: BTreeSet<Authority>,
}

impl AllAuthoritiesRequired {
    /// Creates a bounded all-authorities policy.
    pub fn new(
        authorities: impl IntoIterator<Item = Authority>,
    ) -> Result<Self, AuthorizationBuildError> {
        Ok(Self {
            authorities: authority_set(authorities)?,
        })
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for AllAuthoritiesRequired {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(
            if self
                .authorities
                .iter()
                .all(|authority| context.has_authority(authority))
            {
                AuthorizationDecision::Grant
            } else {
                AuthorizationDecision::Deny
            },
        )
    }
}

/// Policy requiring at least a configured authentication assurance level.
#[derive(Clone, Copy, Debug)]
pub struct MinimumAssurance {
    minimum: AssuranceLevel,
}

impl MinimumAssurance {
    /// Creates a minimum-assurance policy.
    #[must_use]
    pub const fn new(minimum: AssuranceLevel) -> Self {
        Self { minimum }
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for MinimumAssurance {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        ready(
            if context
                .assurance()
                .is_some_and(|assurance| assurance.level() >= self.minimum)
            {
                AuthorizationDecision::Grant
            } else {
                AuthorizationDecision::Deny
            },
        )
    }
}

fn validate_managers<C: ?Sized + Sync>(
    managers: Vec<Arc<dyn AuthorizationManager<C>>>,
) -> Result<Vec<Arc<dyn AuthorizationManager<C>>>, AuthorizationBuildError> {
    if managers.is_empty() {
        return Err(AuthorizationBuildError::NoManagers);
    }
    if managers.len() > MAX_MANAGERS {
        return Err(AuthorizationBuildError::ManagerLimit);
    }
    Ok(managers)
}

/// Deny-overrides conjunction of a non-empty ordered manager list.
///
/// Evaluation short-circuits on denial. Otherwise all grants produce `Grant`,
/// and any abstention produces `Abstain`.
pub struct AllOf<C: ?Sized + Sync> {
    managers: Vec<Arc<dyn AuthorizationManager<C>>>,
}

impl<C: ?Sized + Sync> AllOf<C> {
    /// Validates and constructs a bounded conjunction.
    pub fn new(
        managers: Vec<Arc<dyn AuthorizationManager<C>>>,
    ) -> Result<Self, AuthorizationBuildError> {
        Ok(Self {
            managers: validate_managers(managers)?,
        })
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for AllOf<C> {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            let mut abstained = false;
            for manager in &self.managers {
                match manager.check(context, protected).await? {
                    AuthorizationDecision::Grant => {}
                    AuthorizationDecision::Deny => return Ok(AuthorizationDecision::Deny),
                    AuthorizationDecision::Abstain => abstained = true,
                }
            }
            Ok(if abstained {
                AuthorizationDecision::Abstain
            } else {
                AuthorizationDecision::Grant
            })
        })
    }
}

/// Logical disjunction of a non-empty ordered manager list.
///
/// A grant short-circuits evaluation. In the absence of a grant, one or more
/// denials produce `Deny`; all abstain produces `Abstain`.
pub struct AnyOf<C: ?Sized + Sync> {
    managers: Vec<Arc<dyn AuthorizationManager<C>>>,
}

impl<C: ?Sized + Sync> AnyOf<C> {
    /// Validates and constructs a bounded disjunction.
    pub fn new(
        managers: Vec<Arc<dyn AuthorizationManager<C>>>,
    ) -> Result<Self, AuthorizationBuildError> {
        Ok(Self {
            managers: validate_managers(managers)?,
        })
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for AnyOf<C> {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            let mut denied = false;
            for manager in &self.managers {
                match manager.check(context, protected).await? {
                    AuthorizationDecision::Grant => return Ok(AuthorizationDecision::Grant),
                    AuthorizationDecision::Deny => denied = true,
                    AuthorizationDecision::Abstain => {}
                }
            }
            Ok(if denied {
                AuthorizationDecision::Deny
            } else {
                AuthorizationDecision::Abstain
            })
        })
    }
}

/// Deny-overrides disjunction of a non-empty ordered manager list.
///
/// A denial short-circuits and cannot be hidden by an unrelated grant. In the
/// absence of denial, one or more grants produce `Grant`; all abstain produces
/// `Abstain`. A grant therefore does not short-circuit later denial.
pub struct DenyOverridesAnyOf<C: ?Sized + Sync> {
    managers: Vec<Arc<dyn AuthorizationManager<C>>>,
}

impl<C: ?Sized + Sync> DenyOverridesAnyOf<C> {
    /// Validates and constructs a bounded deny-overrides disjunction.
    pub fn new(
        managers: Vec<Arc<dyn AuthorizationManager<C>>>,
    ) -> Result<Self, AuthorizationBuildError> {
        Ok(Self {
            managers: validate_managers(managers)?,
        })
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for DenyOverridesAnyOf<C> {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            let mut granted = false;
            for manager in &self.managers {
                match manager.check(context, protected).await? {
                    AuthorizationDecision::Grant => granted = true,
                    AuthorizationDecision::Deny => return Ok(AuthorizationDecision::Deny),
                    AuthorizationDecision::Abstain => {}
                }
            }
            Ok(if granted {
                AuthorizationDecision::Grant
            } else {
                AuthorizationDecision::Abstain
            })
        })
    }
}

/// Logical negation preserving abstention and operational failure.
pub struct Not<C: ?Sized + Sync> {
    manager: Arc<dyn AuthorizationManager<C>>,
}

impl<C: ?Sized + Sync> Not<C> {
    /// Wraps one manager for logical negation.
    #[must_use]
    pub const fn new(manager: Arc<dyn AuthorizationManager<C>>) -> Self {
        Self { manager }
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for Not<C> {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            Ok(match self.manager.check(context, protected).await? {
                AuthorizationDecision::Grant => AuthorizationDecision::Deny,
                AuthorizationDecision::Deny => AuthorizationDecision::Grant,
                AuthorizationDecision::Abstain => AuthorizationDecision::Abstain,
            })
        })
    }
}

type Condition<C> = dyn Fn(&SecurityContext, &C) -> bool + Send + Sync;

/// Conditional delegation that abstains when its non-secret predicate is false.
pub struct When<C: ?Sized + Sync> {
    condition: Arc<Condition<C>>,
    manager: Arc<dyn AuthorizationManager<C>>,
    marker: PhantomData<fn(&C)>,
}

impl<C: ?Sized + Sync> When<C> {
    /// Creates conditional delegation from a synchronous predicate and manager.
    #[must_use]
    pub fn new(condition: Arc<Condition<C>>, manager: Arc<dyn AuthorizationManager<C>>) -> Self {
        Self {
            condition,
            manager,
            marker: PhantomData,
        }
    }
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for When<C> {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        if (self.condition)(context, protected) {
            self.manager.check(context, protected)
        } else {
            ready(AuthorizationDecision::Abstain)
        }
    }
}
