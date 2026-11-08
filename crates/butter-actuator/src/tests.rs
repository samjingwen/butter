use super::*;
use butter_core::{
    cleanup::CleanupBudget,
    lifecycle::{ShutdownBudget, ShutdownHandle, Supervisor},
    operation::OperationOwner,
    startup::Startup,
};
use std::{
    convert::Infallible,
    future::{pending, poll_fn},
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::time::advance;

fn policy() -> HealthPolicy {
    HealthPolicy::new(
        Duration::from_secs(2),
        Duration::from_secs(3),
        Duration::from_secs(6),
        Duration::from_secs(1),
    )
    .expect("valid policy")
}
fn supervisor() -> Supervisor {
    let second = Duration::from_secs(1);
    Supervisor::new(
        ShutdownBudget::new(
            second,
            second,
            second,
            CleanupBudget::new(second, second, second).expect("cleanup"),
        )
        .expect("budget"),
    )
}
async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}
fn view(
    reader: HealthReader<()>,
    lifecycle: LifecycleStatus,
    group: ContributorGroup,
) -> RunningActuator {
    RunningActuator {
        lifecycle,
        contributors: vec![Contributor {
            id: ContributorId::new("dependency").expect("identity"),
            group,
            reader,
        }]
        .into(),
    }
}
fn assert_views(view: &RunningActuator, overall: Status, live: Status, ready: Status) {
    assert_eq!(view.health(HealthView::Overall).status, overall);
    assert_eq!(view.health(HealthView::Liveness).status, live);
    assert_eq!(view.health(HealthView::Readiness).status, ready);
}

#[test]
fn identities_catalog_and_inert_duplicate_rejection() {
    for invalid in [
        "",
        "bad/name",
        "secret value",
        "é",
        "query?",
        concat!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
    ] {
        assert_eq!(
            ContributorId::new(invalid),
            Err(BuildError::InvalidIdentity)
        );
        assert_eq!(EndpointId::new(invalid), Err(BuildError::InvalidIdentity));
    }
    for valid in ["store.health", "a-B_9", "health"] {
        assert_eq!(ContributorId::new(valid).expect("valid").as_str(), valid);
        assert_eq!(EndpointId::new(valid).expect("valid").as_str(), valid);
    }
    assert_eq!(
        HEALTH_OPERATIONS.map(|op| op.view),
        [
            HealthView::Overall,
            HealthView::Liveness,
            HealthView::Readiness
        ]
    );
    assert!(
        HEALTH_OPERATIONS
            .iter()
            .all(|op| op.endpoint == EndpointId::HEALTH && op.kind == OperationKind::Read)
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut builder = Actuator::builder();
    let called = calls.clone();
    let id = ContributorId::new("store").expect("id");
    let diagnostics = builder
        .probe(id, ContributorGroup::Readiness, policy(), move || {
            called.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>(()) }
        })
        .expect("register inert");
    assert_eq!(
        builder
            .probe(id, ContributorGroup::Overall, policy(), || async {
                Ok::<_, ()>(())
            })
            .expect_err("duplicate"),
        BuildError::DuplicateContributor
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Unknown);
    drop(builder.build());
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Stopped);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn empty_contributors_follow_the_complete_lifecycle_matrix() {
    use Status::{Down, Up};
    let mut base = supervisor();
    base.register("connector", |startup| async {
        let running = startup.acknowledge_started();
        running.signal().draining().await;
        Ok(running.stopped())
    })
    .expect("connector");
    let status = base.status();
    let view = Actuator::builder()
        .build()
        .register_in(&mut base, status)
        .expect("register");
    assert_views(&view, Down, Up, Down);
    let running = base.start();
    running.status().wait_ready().await.expect("ready");
    assert_views(&view, Up, Up, Up);
    running.handle().request();
    assert_views(&view, Down, Up, Down);
    running.shutdown_checked().await.expect("checked shutdown");
    assert_views(&view, Down, Down, Down);
}

#[tokio::test(start_paused = true)]
async fn every_core_state_maps_down_except_fresh_success_and_liveness_ignores_it() {
    use Status::{Down, Up};
    let attempts = Arc::new(AtomicUsize::new(0));
    let called = attempts.clone();
    let monitor = HealthMonitor::new(policy(), move || {
        let attempt = called.fetch_add(1, Ordering::SeqCst);
        async move {
            match attempt {
                0 => Ok(()),
                1 => Err(()),
                _ => pending().await,
            }
        }
    });
    let reader = monitor.reader();
    let (control, approval) = ShutdownHandle::new_with_readiness_approval();
    approval.approve();
    let readiness = view(
        reader.clone(),
        control.status(),
        ContributorGroup::Readiness,
    );
    let overall_only = view(reader.clone(), control.status(), ContributorGroup::Overall);
    let mut run = Box::pin(monitor.run(control.signal()));
    assert_eq!(reader.snapshot().status(), HealthStatus::Unknown);
    assert_views(&readiness, Down, Up, Down);
    assert_views(&overall_only, Down, Up, Up);
    assert!(poll_once(run.as_mut()).await.is_pending());
    assert_eq!(reader.snapshot().status(), HealthStatus::Healthy);
    assert_views(&readiness, Up, Up, Up);
    let completed = reader
        .snapshot()
        .last_probe()
        .expect("probe")
        .completed_at();
    for _ in 0..100 {
        assert_views(&readiness, Up, Up, Up);
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    advance(Duration::from_secs(6)).await;
    assert_eq!(reader.snapshot().status(), HealthStatus::Stale);
    assert_eq!(
        reader
            .snapshot()
            .last_probe()
            .expect("same probe")
            .completed_at(),
        completed
    );
    assert_views(&readiness, Down, Up, Down);
    assert!(poll_once(run.as_mut()).await.is_pending());
    assert_eq!(reader.snapshot().status(), HealthStatus::Failed);
    assert_views(&readiness, Down, Up, Down);
    assert_views(&overall_only, Down, Up, Up);
    advance(Duration::from_secs(3)).await;
    assert!(poll_once(run.as_mut()).await.is_pending());
    advance(Duration::from_secs(2)).await;
    assert!(poll_once(run.as_mut()).await.is_pending());
    assert_eq!(reader.snapshot().status(), HealthStatus::TimedOut);
    assert_views(&readiness, Down, Up, Down);
    control.request();
    run.await;
    assert_eq!(reader.snapshot().status(), HealthStatus::Stopped);
    // A separate ready lifecycle proves writer stop itself contributes DOWN.
    let (ready, approval) = ShutdownHandle::new_with_readiness_approval();
    approval.approve();
    assert_views(
        &view(reader, ready.status(), ContributorGroup::Readiness),
        Down,
        Up,
        Down,
    );
}

#[derive(Debug)]
struct Secret(&'static str);

#[tokio::test]
async fn protected_registration_preserves_concrete_diagnostics_and_order_without_disclosure() {
    let mut builder = Actuator::builder();
    let diagnostics = builder
        .probe(
            ContributorId::new("store").expect("id"),
            ContributorGroup::Readiness,
            policy(),
            || async { Err(Secret("synthetic-secret-marker")) },
        )
        .expect("probe");
    let second = builder
        .probe(
            ContributorId::new("optional").expect("id"),
            ContributorGroup::Overall,
            policy(),
            || async { Ok::<_, ()>(()) },
        )
        .expect("probe");
    let base = supervisor();
    let status = base.status();
    let second_duration = Duration::from_secs(1);
    let cleanup =
        CleanupBudget::new(second_duration, second_duration, second_duration).expect("cleanup");
    let mut starting = Startup::protected(
        base,
        OperationOwner::new(second_duration * 5)
            .expect("owner")
            .into_context(),
        cleanup,
        async move |scope| Ok::<_, RegistrationError>(builder.build().register_in(scope, status)?),
    )
    .start();
    let (running, view) = starting.wait_with_output().await.expect("startup");
    running
        .status()
        .wait_ready()
        .await
        .expect("monitor startup not dependency success");
    tokio::time::timeout(second_duration * 5, async {
        while diagnostics.snapshot().status() != HealthStatus::Failed
            || second.snapshot().status() != HealthStatus::Healthy
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("publication");
    assert_eq!(
        view.contributor_ids()
            .map(ContributorId::as_str)
            .collect::<Vec<_>>(),
        ["store", "optional"]
    );
    assert_eq!(
        diagnostics.last_failure().expect("concrete cause").0,
        "synthetic-secret-marker"
    );
    for text in [
        format!("{diagnostics:?}"),
        format!("{view:?}"),
        format!("{:?}", view.health(HealthView::Overall)),
    ] {
        assert!(!text.contains("synthetic-secret-marker"));
    }
    assert_views(&view, Status::Down, Status::Up, Status::Down);
    running.shutdown_checked().await.expect("settled monitors");
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Stopped);
    assert!(diagnostics.last_failure().is_some());
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn sequential_sampling_timeout_and_pending_probe_cancellation_settle_ownership() {
    let active = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (active_probe, calls_probe) = (active.clone(), calls.clone());
    let mut builder = Actuator::builder();
    let diagnostics = builder
        .probe(
            ContributorId::new("pending").expect("id"),
            ContributorGroup::Readiness,
            policy(),
            move || {
                assert_eq!(active_probe.fetch_add(1, Ordering::SeqCst), 0);
                calls_probe.fetch_add(1, Ordering::SeqCst);
                let guard = Active(active_probe.clone());
                async move {
                    let _guard = guard;
                    pending::<Result<(), ()>>().await
                }
            },
        )
        .expect("probe");
    // Exercise the actual erased registration, not another sampling implementation.
    let mut base = supervisor();
    let status = base.status();
    let view = builder
        .build()
        .register_in(&mut base, status)
        .expect("register");
    let running = base.start();
    running
        .status()
        .wait_ready()
        .await
        .expect("ready with unknown dependency");
    assert_eq!(active.load(Ordering::SeqCst), 1);
    advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::TimedOut);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    advance(Duration::from_secs(100)).await;
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "no catch-up or overlap");
    assert_eq!(active.load(Ordering::SeqCst), 1);
    assert_views(&view, Status::Down, Status::Up, Status::Down);
    running
        .shutdown_checked()
        .await
        .expect("cancel pending future");
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Stopped);
    assert_views(&view, Status::Down, Status::Down, Status::Down);
}

#[test]
fn rejected_component_registration_never_invokes_a_probe() {
    let mut base = supervisor();
    base.register("store", |startup| async { Ok(startup.abandon()) })
        .expect("existing");
    let mut builder = Actuator::builder();
    let diagnostics = builder
        .probe(
            ContributorId::new("store").expect("id"),
            ContributorGroup::Readiness,
            policy(),
            || -> std::future::Ready<Result<(), ()>> { panic!("must stay inert") },
        )
        .expect("plan");
    let status = base.status();
    assert!(builder.build().register_in(&mut base, status).is_err());
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Stopped);
}

#[test]
fn final_lifecycle_read_overrides_success_and_liveness_never_iterates_dependencies() {
    let (control, approval) = ShutdownHandle::new_with_readiness_approval();
    approval.approve();
    let observations = std::iter::once_with(|| {
        control.request();
        HealthStatus::Healthy
    });
    assert_eq!(
        evaluate(HealthView::Readiness, observations, || control
            .status()
            .readiness())
        .status,
        Status::Down
    );
    let forbidden = std::iter::once_with(|| panic!("liveness must never read dependency state"));
    assert_eq!(
        evaluate(HealthView::Liveness, forbidden, || Readiness::Draining).status,
        Status::Up
    );
}

#[test]
fn contributor_count_is_bounded_before_registration() {
    let mut builder = Actuator::builder();
    for index in 0..64 {
        let name = Box::leak(format!("contributor.{index}").into_boxed_str());
        builder
            .probe(
                ContributorId::new(name).expect("id"),
                ContributorGroup::Overall,
                policy(),
                || async { Ok::<_, ()>(()) },
            )
            .expect("within limit");
    }
    assert_eq!(
        builder
            .probe(
                ContributorId::new("overflow").expect("id"),
                ContributorGroup::Overall,
                policy(),
                || async { Ok::<_, ()>(()) }
            )
            .expect_err("bounded"),
        BuildError::ContributorLimit
    );
}
