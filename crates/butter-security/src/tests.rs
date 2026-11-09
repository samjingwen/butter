use crate::*;
use std::{
    error::Error,
    future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::SystemTime,
};
use zeroize::Zeroize;

type TestResult = Result<(), Box<dyn Error>>;

fn test_mechanism() -> Result<AuthenticationMechanism, AuthenticationBuildError> {
    AuthenticationMechanism::new("synthetic")
}

fn test_authentication(
    subject: &str,
    authorities: &[&str],
    assurance: AssuranceLevel,
) -> Result<Authentication, Box<dyn Error>> {
    let principal: Arc<dyn Principal> = Arc::new(NamedPrincipal::new(
        SubjectId::new(subject)?,
        Some(DisplayName::new("Synthetic caller")?),
    ));
    let mut builder = Authentication::builder(
        principal,
        test_mechanism()?,
        SystemTime::UNIX_EPOCH,
        Assurance::new(assurance),
    );
    for authority in authorities {
        builder.authority(Authority::new(*authority)?)?;
    }
    Ok(builder.build())
}

#[derive(Clone)]
struct OutcomeProvider {
    outcome: Result<ProviderOutcome, AuthenticationOperationalError>,
    calls: Arc<AtomicUsize>,
}

impl OutcomeProvider {
    fn new(outcome: Result<ProviderOutcome, AuthenticationOperationalError>) -> Self {
        Self {
            outcome,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl AuthenticationProvider for OutcomeProvider {
    fn authenticate<'a>(&'a self, _request: &'a dyn AuthenticationRequest) -> ProviderFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let outcome = self.outcome.clone();
        Box::pin(async move { outcome })
    }
}

fn provider_manager(
    providers: impl IntoIterator<Item = Arc<dyn AuthenticationProvider>>,
) -> Result<ProviderManager, ProviderManagerBuildError> {
    let mut builder = ProviderManager::builder();
    for provider in providers {
        builder.provider(provider)?;
    }
    builder.build()
}

#[tokio::test]
async fn provider_manager_falls_back_only_after_unsupported() -> TestResult {
    let first = OutcomeProvider::new(Ok(ProviderOutcome::Unsupported));
    let expected = test_authentication(
        "subject-1",
        &["records.read"],
        AssuranceLevel::SINGLE_FACTOR,
    )?;
    let second = OutcomeProvider::new(Ok(ProviderOutcome::Authenticated(expected)));
    let manager = provider_manager([
        Arc::new(first.clone()) as Arc<dyn AuthenticationProvider>,
        Arc::new(second.clone()),
    ])?;
    let request = CredentialRequest::new(test_mechanism()?, String::from("private-value"));

    let result = manager.authenticate(&request).await?;

    assert_eq!(result.principal().subject().as_str(), "subject-1");
    assert_eq!(first.calls(), 1);
    assert_eq!(second.calls(), 1);
    Ok(())
}

#[tokio::test]
async fn recognized_rejection_is_terminal() -> TestResult {
    let rejecting = OutcomeProvider::new(Ok(ProviderOutcome::Rejected(
        AuthenticationRejection::InvalidCredentials,
    )));
    let accepting = OutcomeProvider::new(Ok(ProviderOutcome::Authenticated(test_authentication(
        "subject-2",
        &[],
        AssuranceLevel::SINGLE_FACTOR,
    )?)));
    let manager = provider_manager([
        Arc::new(rejecting.clone()) as Arc<dyn AuthenticationProvider>,
        Arc::new(accepting.clone()),
    ])?;
    let request = CredentialRequest::new(test_mechanism()?, String::from("wrong-value"));

    let result = manager.authenticate(&request).await;

    assert!(matches!(
        result,
        Err(AuthenticationFailure::Rejected(
            AuthenticationRejection::InvalidCredentials
        ))
    ));
    assert_eq!(rejecting.calls(), 1);
    assert_eq!(accepting.calls(), 0);
    Ok(())
}

#[tokio::test]
async fn all_unsupported_is_a_typed_failure() -> TestResult {
    let manager = provider_manager([
        Arc::new(OutcomeProvider::new(Ok(ProviderOutcome::Unsupported)))
            as Arc<dyn AuthenticationProvider>,
        Arc::new(OutcomeProvider::new(Ok(ProviderOutcome::Unsupported))),
    ])?;
    let request = CredentialRequest::new(test_mechanism()?, String::from("private-value"));

    assert!(matches!(
        manager.authenticate(&request).await,
        Err(AuthenticationFailure::UnsupportedMechanism)
    ));
    Ok(())
}

#[tokio::test]
async fn operational_failure_is_terminal_and_distinct() -> TestResult {
    let unavailable = OutcomeProvider::new(Err(AuthenticationOperationalError::Unavailable));
    let later = OutcomeProvider::new(Ok(ProviderOutcome::Unsupported));
    let manager = provider_manager([
        Arc::new(unavailable.clone()) as Arc<dyn AuthenticationProvider>,
        Arc::new(later.clone()),
    ])?;
    let request = CredentialRequest::new(test_mechanism()?, String::from("private-value"));

    assert!(matches!(
        manager.authenticate(&request).await,
        Err(AuthenticationFailure::Operational(
            AuthenticationOperationalError::Unavailable
        ))
    ));
    assert_eq!(later.calls(), 0);
    Ok(())
}

#[derive(Debug)]
struct ObservedSecret {
    bytes: Vec<u8>,
    zeroized_before_drop: Arc<AtomicBool>,
}

impl Zeroize for ObservedSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for ObservedSecret {
    fn drop(&mut self) {
        self.zeroized_before_drop
            .store(self.bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
    }
}

#[test]
fn credentials_redact_formatting_and_zeroize_on_drop() -> TestResult {
    let secret = "unique-private-credential";
    let observed = Arc::new(AtomicBool::new(false));
    {
        let credential = Credential::new(ObservedSecret {
            bytes: secret.as_bytes().to_vec(),
            zeroized_before_drop: Arc::clone(&observed),
        });
        let request = CredentialRequest::new(test_mechanism()?, String::from(secret));

        assert_eq!(format!("{credential:?}"), "Credential([REDACTED])");
        assert!(!format!("{request:?}").contains(secret));
        assert_eq!(request.credential(), secret);
    }
    assert!(observed.load(Ordering::SeqCst));
    Ok(())
}

struct PendingProvider {
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

struct DropSignal(Arc<AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl AuthenticationProvider for PendingProvider {
    fn authenticate<'a>(&'a self, _request: &'a dyn AuthenticationRequest) -> ProviderFuture<'a> {
        let started = Arc::clone(&self.started);
        let dropped = Arc::clone(&self.dropped);
        Box::pin(async move {
            let _drop_signal = DropSignal(dropped);
            started.store(true, Ordering::SeqCst);
            future::pending::<Result<ProviderOutcome, AuthenticationOperationalError>>().await
        })
    }
}

#[tokio::test]
async fn dropping_manager_future_drops_active_provider_future() -> TestResult {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let manager = provider_manager([Arc::new(PendingProvider {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
    }) as Arc<dyn AuthenticationProvider>])?;
    let request = CredentialRequest::new(test_mechanism()?, String::from("private-value"));
    let mut authentication = Box::pin(manager.authenticate(&request));

    tokio::select! {
        biased;
        result = &mut authentication => panic!("pending provider completed: {result:?}"),
        () = async {} => {}
    }
    assert!(started.load(Ordering::SeqCst));
    assert!(!dropped.load(Ordering::SeqCst));

    drop(authentication);
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[derive(Default)]
struct RecordingSink(Mutex<Vec<SecurityEvent>>);

impl SecurityEventSink for RecordingSink {
    fn publish(&self, event: SecurityEvent) {
        if let Ok(mut events) = self.0.lock() {
            events.push(event);
        }
    }
}

impl RecordingSink {
    fn snapshot(&self) -> Vec<SecurityEvent> {
        match self.0.lock() {
            Ok(events) => events.clone(),
            Err(_) => panic!("recording event sink lock poisoned"),
        }
    }
}

#[tokio::test]
async fn authentication_events_are_typed_and_credential_free() -> TestResult {
    let secret = "event-must-not-contain-this";
    let sink = Arc::new(RecordingSink::default());
    let provider = OutcomeProvider::new(Ok(ProviderOutcome::Rejected(
        AuthenticationRejection::NotPermitted,
    )));
    let mut builder = ProviderManager::builder();
    builder.provider(Arc::new(provider))?;
    builder.event_sink(Arc::clone(&sink) as Arc<dyn SecurityEventSink>);
    let manager = builder.build()?;
    let request = CredentialRequest::new(test_mechanism()?, String::from(secret));

    let _result = manager.authenticate(&request).await;
    let events = sink.snapshot();

    assert_eq!(events.len(), 1);
    assert!(!format!("{events:?}").contains(secret));
    assert!(matches!(
        events.first(),
        Some(SecurityEvent::Authentication(AuthenticationEvent::Rejected(event)))
            if event.rejection() == AuthenticationRejection::NotPermitted
    ));
    Ok(())
}

struct StaticDecision(AuthorizationDecision);

impl<C: ?Sized + Sync> AuthorizationManager<C> for StaticDecision {
    fn check<'a>(
        &'a self,
        _context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        let decision = self.0;
        Box::pin(async move { Ok(decision) })
    }
}

fn policy(decision: AuthorizationDecision) -> Arc<dyn AuthorizationManager<()>> {
    Arc::new(StaticDecision(decision))
}

#[tokio::test]
async fn all_abstain_denies_by_default() -> TestResult {
    let managers = vec![
        policy(AuthorizationDecision::Abstain),
        policy(AuthorizationDecision::Abstain),
    ];
    let manager = AnyOf::new(managers)?;

    let decision = manager.check(&SecurityContext::anonymous(), &()).await?;
    let enforced = authorize(&manager, &SecurityContext::anonymous(), &()).await;

    assert_eq!(decision, AuthorizationDecision::Abstain);
    assert_eq!(enforced, Err(AuthorizationFailure::NoGrant));
    Ok(())
}

#[tokio::test]
async fn any_of_does_not_hide_denial_behind_grant() -> TestResult {
    let manager = AnyOf::new(vec![
        policy(AuthorizationDecision::Grant),
        policy(AuthorizationDecision::Deny),
    ])?;

    assert_eq!(
        manager.check(&SecurityContext::anonymous(), &()).await?,
        AuthorizationDecision::Deny
    );
    Ok(())
}

struct CountingDecision {
    decision: AuthorizationDecision,
    calls: Arc<AtomicUsize>,
}

impl<C: ?Sized + Sync> AuthorizationManager<C> for CountingDecision {
    fn check<'a>(
        &'a self,
        _context: &'a SecurityContext,
        _protected: &'a C,
    ) -> AuthorizationFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let decision = self.decision;
        Box::pin(async move { Ok(decision) })
    }
}

#[tokio::test]
async fn all_of_short_circuits_on_denial() -> TestResult {
    let skipped_calls = Arc::new(AtomicUsize::new(0));
    let skipped: Arc<dyn AuthorizationManager<()>> = Arc::new(CountingDecision {
        decision: AuthorizationDecision::Grant,
        calls: Arc::clone(&skipped_calls),
    });
    let manager = AllOf::new(vec![
        policy(AuthorizationDecision::Grant),
        policy(AuthorizationDecision::Deny),
        skipped,
    ])?;

    assert_eq!(
        manager.check(&SecurityContext::anonymous(), &()).await?,
        AuthorizationDecision::Deny
    );
    assert_eq!(skipped_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn standard_managers_use_exact_authorities_and_assurance() -> TestResult {
    let context = test_authentication(
        "subject-3",
        &["records.read", "records.write"],
        AssuranceLevel::MULTI_FACTOR,
    )?
    .into_context();
    let exact = AuthorityRequired::new(Authority::new("records.read")?);
    let wrong_case = AuthorityRequired::new(Authority::new("Records.Read")?);
    let any =
        AnyAuthorityRequired::new([Authority::new("missing")?, Authority::new("records.write")?])?;
    let all = AllAuthoritiesRequired::new([
        Authority::new("records.read")?,
        Authority::new("records.write")?,
    ])?;
    let assurance = MinimumAssurance::new(AssuranceLevel::MULTI_FACTOR);

    assert_eq!(
        exact.check(&context, &()).await?,
        AuthorizationDecision::Grant
    );
    assert_eq!(
        wrong_case.check(&context, &()).await?,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        any.check(&context, &()).await?,
        AuthorizationDecision::Grant
    );
    assert_eq!(
        all.check(&context, &()).await?,
        AuthorizationDecision::Grant
    );
    assert_eq!(
        assurance.check(&context, &()).await?,
        AuthorizationDecision::Grant
    );
    assert_eq!(
        AnonymousRequired.check(&context, &()).await?,
        AuthorizationDecision::Deny
    );
    assert_eq!(
        AuthenticatedRequired.check(&context, &()).await?,
        AuthorizationDecision::Grant
    );
    Ok(())
}

#[tokio::test]
async fn not_and_when_preserve_abstention() -> TestResult {
    let not = Not::new(policy(AuthorizationDecision::Abstain));
    let conditional = When::new(
        Arc::new(|_context: &SecurityContext, applies: &bool| *applies),
        Arc::new(PermitAll),
    );

    assert_eq!(
        not.check(&SecurityContext::anonymous(), &()).await?,
        AuthorizationDecision::Abstain
    );
    assert_eq!(
        conditional
            .check(&SecurityContext::anonymous(), &false)
            .await?,
        AuthorizationDecision::Abstain
    );
    assert_eq!(
        conditional
            .check(&SecurityContext::anonymous(), &true)
            .await?,
        AuthorizationDecision::Grant
    );
    Ok(())
}

struct PendingAuthorization {
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl AuthorizationManager<()> for PendingAuthorization {
    fn check<'a>(
        &'a self,
        _context: &'a SecurityContext,
        _protected: &'a (),
    ) -> AuthorizationFuture<'a> {
        let started = Arc::clone(&self.started);
        let dropped = Arc::clone(&self.dropped);
        Box::pin(async move {
            let _drop_signal = DropSignal(dropped);
            started.store(true, Ordering::SeqCst);
            future::pending::<Result<AuthorizationDecision, AuthorizationOperationalError>>().await
        })
    }
}

#[tokio::test]
async fn dropping_authorization_future_drops_active_policy_future() -> TestResult {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let manager = PendingAuthorization {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
    };
    let context = SecurityContext::anonymous();
    let mut authorization = Box::pin(authorize(&manager, &context, &()));

    tokio::select! {
        biased;
        result = &mut authorization => panic!("pending policy completed: {result:?}"),
        () = async {} => {}
    }
    assert!(started.load(Ordering::SeqCst));
    assert!(!dropped.load(Ordering::SeqCst));

    drop(authorization);
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn identities_are_bounded_without_echoing_rejected_values() -> TestResult {
    let rejected = "x".repeat(257);
    let error = SubjectId::new(rejected.clone()).err();

    assert_eq!(error, Some(IdentityError::InvalidSubject));
    assert!(!format!("{error:?}").contains(&rejected));
    assert_eq!(Authority::new("records.read")?.as_str(), "records.read");
    assert_ne!(
        Authority::new("records.read")?,
        Authority::new("Records.Read")?
    );
    Ok(())
}

#[test]
fn principal_supports_safe_typed_downcast() -> TestResult {
    let principal = NamedPrincipal::new(SubjectId::new("subject-4")?, None);
    let erased: &dyn Principal = &principal;

    let recovered = erased.downcast_ref::<NamedPrincipal>();

    assert!(recovered.is_some());
    assert_eq!(erased.subject().as_str(), "subject-4");
    Ok(())
}

#[test]
fn explicit_builders_reject_empty_composition() {
    assert!(matches!(
        ProviderManager::builder().build(),
        Err(ProviderManagerBuildError::NoProviders)
    ));
    assert!(matches!(
        AnyOf::<()>::new(Vec::new()),
        Err(AuthorizationBuildError::NoManagers)
    ));
    assert!(matches!(
        AnyAuthorityRequired::new(Vec::new()),
        Err(AuthorizationBuildError::NoAuthorities)
    ));
}

#[test]
fn value_and_composition_limits_are_enforced_before_extra_input() -> TestResult {
    assert!(AuthenticationMechanism::new("m".repeat(64)).is_ok());
    assert_eq!(
        AuthenticationMechanism::new("m".repeat(65)),
        Err(AuthenticationBuildError::InvalidMechanism)
    );
    assert_eq!(
        AuthenticationMechanism::new("méchanism"),
        Err(AuthenticationBuildError::InvalidMechanism)
    );
    assert!(Authority::new("a".repeat(128)).is_ok());
    assert_eq!(
        Authority::new("a".repeat(129)),
        Err(IdentityError::InvalidAuthority)
    );
    assert_eq!(
        AssuranceLevel::new(0),
        Err(AuthenticationBuildError::InvalidAssuranceLevel)
    );

    let authorities = (0..=256)
        .map(|index| Authority::new(format!("authority-{index}")))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(
        AnyAuthorityRequired::new(authorities),
        Err(AuthorizationBuildError::AuthorityLimit)
    ));

    let provider: Arc<dyn AuthenticationProvider> =
        Arc::new(OutcomeProvider::new(Ok(ProviderOutcome::Unsupported)));
    let mut providers = ProviderManager::builder();
    for _ in 0..64 {
        providers.provider(Arc::clone(&provider))?;
    }
    assert_eq!(
        providers.provider(provider).err(),
        Some(ProviderManagerBuildError::ProviderLimit)
    );

    let managers = (0..=64)
        .map(|_| policy(AuthorizationDecision::Abstain))
        .collect();
    assert!(matches!(
        AnyOf::new(managers),
        Err(AuthorizationBuildError::ManagerLimit)
    ));
    Ok(())
}
