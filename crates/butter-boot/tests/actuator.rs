//! Public API acceptance over real owned loopback connections.
#![cfg(feature = "actuator")]

use butter_actuator::{Actuator, ContributorDiagnostics, ContributorGroup, ContributorId};
use butter_boot::Application;
use butter_core::health::{HealthPolicy, HealthStatus};
use butter_web::{
    RouteInventory, Router, native,
    routing::{get, post},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Notify, watch},
};

const PATHS: [&str; 3] = [
    "/actuator/health",
    "/actuator/health/liveness",
    "/actuator/health/readiness",
];
fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}
fn policy() -> HealthPolicy {
    HealthPolicy::new(
        Duration::from_millis(100),
        Duration::from_millis(20),
        Duration::from_secs(5),
        Duration::from_millis(10),
    )
    .expect("policy")
}
async fn request(address: SocketAddr, method: &str, path: &str) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address).await.expect("connect owned listener");
        stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await.expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).await.expect("read");
        response
    }).await.expect("bounded HTTP")
}
fn assert_health(response: &str, code: u16, status: &str, head: bool) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {code}")),
        "{response}"
    );
    let (headers, body) = response.split_once("\r\n\r\n").expect("HTTP parts");
    let headers = headers.to_ascii_lowercase();
    assert!(
        headers.contains("content-type: application/json\r\n")
            || headers.ends_with("content-type: application/json"),
        "{headers}"
    );
    assert!(headers.contains("cache-control: no-store"), "{headers}");
    assert_eq!(
        body,
        if head {
            String::new()
        } else {
            format!(r#"{{"status":"{status}"}}"#)
        }
    );
    assert!(!response.contains("synthetic-private-marker"));
}
async fn wait_status<E>(diagnostics: &ContributorDiagnostics<E>, status: HealthStatus) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while diagnostics.snapshot().status() != status {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("health publication");
}

#[tokio::test]
async fn explicit_attachment_json_head_methods_queries_legacy_removal_and_checked_shutdown() {
    let running = Application::new(Router::new())
        .bind(loopback())
        .actuator(Actuator::builder().build())
        .expect("attach")
        .start()
        .await
        .expect("start");
    let address = running.address();
    for path in PATHS {
        assert_health(&request(address, "GET", path).await, 200, "UP", false);
        assert_health(&request(address, "HEAD", path).await, 200, "UP", true);
        assert_health(
            &request(address, "GET", &format!("{path}?details=true&probe=now")).await,
            200,
            "UP",
            false,
        );
        for method in ["POST", "PUT", "DELETE", "OPTIONS"] {
            let response = request(address, method, path).await;
            assert!(
                response.starts_with("HTTP/1.1 405"),
                "{method} {path}: {response}"
            );
            assert!(response.to_ascii_lowercase().contains("allow: get,head"));
        }
    }
    for path in [
        "/live",
        "/ready",
        "/actuator",
        "/actuator/",
        "/actuator/info",
        "/actuator/health/unknown",
    ] {
        assert!(
            request(address, "GET", path)
                .await
                .starts_with("HTTP/1.1 404"),
            "{path}"
        );
    }
    running.shutdown().await.expect("checked shutdown");
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn feature_unification_without_attachment_has_no_route_or_subtree_effect() {
    let running = Application::new(Router::new())
        .bind(loopback())
        .start()
        .await
        .expect("start");
    for path in PATHS {
        assert!(
            request(running.address(), "GET", path)
                .await
                .starts_with("HTTP/1.1 404")
        );
    }
    running.shutdown().await.expect("shutdown");
    let running =
        Application::new(Router::new().route("/actuator/custom", get(|| async { "ordinary" })))
            .bind(loopback())
            .start()
            .await
            .expect("no reservation without attachment");
    assert!(
        request(running.address(), "GET", "/actuator/custom")
            .await
            .ends_with("ordinary")
    );
    running.shutdown().await.expect("shutdown");
    assert!(
        Application::new(Router::new())
            .actuator(Actuator::builder().build())
            .expect("first")
            .actuator(Actuator::builder().build())
            .is_err()
    );
}

#[derive(Debug)]
struct PrivateFailure(&'static str);
#[derive(Clone, Copy)]
enum Mode {
    Up,
    Down,
    Blocked,
}
fn contributor(
    builder: &mut butter_actuator::ActuatorBuilder,
    name: &'static str,
    group: ContributorGroup,
) -> (
    watch::Sender<Mode>,
    ContributorDiagnostics<PrivateFailure>,
    Arc<AtomicUsize>,
    Arc<Notify>,
) {
    let (control, receiver) = watch::channel(Mode::Blocked);
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(Notify::new());
    let (called, started) = (calls.clone(), entered.clone());
    let diagnostics = builder
        .probe(
            ContributorId::new(name).expect("id"),
            group,
            policy(),
            move || {
                called.fetch_add(1, Ordering::SeqCst);
                let mode = *receiver.borrow();
                let started = started.clone();
                async move {
                    started.notify_one();
                    match mode {
                        Mode::Up => Ok(()),
                        Mode::Down => Err(PrivateFailure("synthetic-private-marker")),
                        Mode::Blocked => std::future::pending().await,
                    }
                }
            },
        )
        .expect("contributor");
    (control, diagnostics, calls, entered)
}

#[tokio::test]
async fn selected_readiness_outage_timeout_recovery_and_local_error_redaction() {
    let mut builder = Actuator::builder();
    let (first, diagnostics, _, _) =
        contributor(&mut builder, "first", ContributorGroup::Readiness);
    let (second, second_diagnostics, _, _) =
        contributor(&mut builder, "second", ContributorGroup::Readiness);
    let (overall, overall_diagnostics, _, _) =
        contributor(&mut builder, "summary", ContributorGroup::Overall);
    first.send(Mode::Up).expect("mode");
    second.send(Mode::Down).expect("mode");
    overall.send(Mode::Up).expect("mode");
    let running = Application::new(Router::new())
        .bind(loopback())
        .actuator(builder.build())
        .expect("attach")
        .start()
        .await
        .expect("start while dependency unavailable");
    let address = running.address();
    wait_status(&diagnostics, HealthStatus::Healthy).await;
    wait_status(&second_diagnostics, HealthStatus::Failed).await;
    wait_status(&overall_diagnostics, HealthStatus::Healthy).await;
    assert_health(&request(address, "GET", PATHS[0]).await, 503, "DOWN", false);
    assert_health(&request(address, "GET", PATHS[1]).await, 200, "UP", false);
    assert_health(&request(address, "HEAD", PATHS[2]).await, 503, "DOWN", true);
    assert_eq!(
        second_diagnostics.last_failure().expect("trusted cause").0,
        "synthetic-private-marker"
    );
    assert!(!format!("{second_diagnostics:?}").contains("synthetic-private-marker"));
    second.send(Mode::Up).expect("recover");
    wait_status(&second_diagnostics, HealthStatus::Healthy).await;
    assert_health(&request(address, "GET", PATHS[2]).await, 200, "UP", false);
    overall.send(Mode::Down).expect("overall only outage");
    wait_status(&overall_diagnostics, HealthStatus::Failed).await;
    assert_health(&request(address, "GET", PATHS[0]).await, 503, "DOWN", false);
    assert_health(&request(address, "GET", PATHS[2]).await, 200, "UP", false);
    first.send(Mode::Blocked).expect("timeout");
    wait_status(&diagnostics, HealthStatus::TimedOut).await;
    assert_health(&request(address, "GET", PATHS[2]).await, 503, "DOWN", false);
    first.send(Mode::Up).expect("recover timeout");
    wait_status(&diagnostics, HealthStatus::Healthy).await;
    assert_health(&request(address, "GET", PATHS[2]).await, 200, "UP", false);
    running.shutdown().await.expect("monitors settle");
    for state in [
        diagnostics.snapshot(),
        second_diagnostics.snapshot(),
        overall_diagnostics.snapshot(),
    ] {
        assert_eq!(state.status(), HealthStatus::Stopped);
    }
}

#[tokio::test]
async fn blocked_probe_does_not_block_or_get_triggered_by_endpoint_reads() {
    let mut builder = Actuator::builder();
    let calls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let (called, ended) = (calls.clone(), dropped.clone());
    let slow = HealthPolicy::new(
        Duration::from_secs(60),
        Duration::from_secs(60),
        Duration::from_secs(121),
        Duration::from_secs(1),
    )
    .expect("slow");
    let diagnostics = builder
        .probe(
            ContributorId::new("blocked").expect("id"),
            ContributorGroup::Readiness,
            slow,
            move || {
                called.fetch_add(1, Ordering::SeqCst);
                let guard = Guard(ended.clone());
                async move {
                    let _guard = guard;
                    std::future::pending::<Result<(), ()>>().await
                }
            },
        )
        .expect("probe");
    let running = Application::new(Router::new())
        .bind(loopback())
        .actuator(builder.build())
        .expect("attach")
        .start()
        .await
        .expect("start without first success");
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Unknown);
    for _ in 0..10 {
        assert_health(
            &request(running.address(), "GET", PATHS[2]).await,
            503,
            "DOWN",
            false,
        );
        assert_health(
            &request(running.address(), "GET", PATHS[1]).await,
            200,
            "UP",
            false,
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    running.shutdown().await.expect("cancel active probe");
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Stopped);
}

#[tokio::test]
async fn subtree_conflicts_exact_nested_capture_wildcard_and_declared_inventory_fail_assembly() {
    let declared = Router::from_router(
        native::Router::new().route("/actuator/custom", get(|| async { "no" })),
        RouteInventory::new(["/actuator/custom"]).expect("inventory"),
    );
    let routers = [
        Router::new().route("/actuator/", get(|| async { "no" })),
        Router::new().route("/actuator", get(|| async { "no" })),
        Router::new().route("/actuator/health", post(|| async { "no" })),
        Router::new().route("/actuator/custom", get(|| async { "no" })),
        Router::new().nest(
            "/actuator",
            Router::new().route("/other", get(|| async { "no" })),
        ),
        Router::new().route("/{name}/custom", get(|| async { "no" })),
        Router::new().route("/{*path}", get(|| async { "no" })),
        declared,
    ];
    // Keep the port occupied: assembly must report overlap, not attempt bind.
    let blocker = tokio::net::TcpListener::bind(loopback())
        .await
        .expect("blocker");
    let address = blocker.local_addr().expect("address");
    for routes in routers {
        let error = match Application::new(routes)
            .bind(address)
            .actuator(Actuator::builder().build())
            .expect("attach")
            .start()
            .await
        {
            Ok(_) => panic!("conflict accepted"),
            Err(error) => error,
        };
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
        let mut overlap = false;
        while let Some(error) = cause {
            overlap |= error
                .downcast_ref::<butter_web::BoundaryAssemblyError>()
                .is_some();
            cause = error.source();
        }
        assert!(overlap, "must fail inventory assembly before bind: {error}");
    }
}

#[tokio::test]
async fn attached_public_reads_preserve_application_capture_fallback_admission_and_deadline() {
    let application = Router::new()
        .route(
            "/items/{id}",
            get(|native::extract::Path(id): native::extract::Path<String>| async move { id }),
        )
        .route("/actuatorial", get(|| async { "not reserved" }))
        .route(
            "/slow",
            get(|| async { std::future::pending::<String>().await }),
        )
        .fallback(|| async { (native::http::StatusCode::NOT_FOUND, "application fallback") });
    let running = Application::new(application)
        .bind(loopback())
        .request_budget(
            butter_web::ResponseConstructionBudget::new(Duration::from_millis(20)).expect("budget"),
        )
        .actuator(Actuator::builder().build())
        .expect("attach")
        .start()
        .await
        .expect("start");
    assert!(
        request(running.address(), "GET", "/items/captured")
            .await
            .ends_with("captured")
    );
    assert!(
        request(running.address(), "GET", "/actuatorial")
            .await
            .ends_with("not reserved")
    );
    assert!(
        request(running.address(), "GET", "/absent")
            .await
            .ends_with("application fallback")
    );
    assert!(
        !request(running.address(), "GET", "/actuator/absent")
            .await
            .contains("application fallback")
    );
    assert!(
        !request(running.address(), "GET", "/actuator/")
            .await
            .contains("application fallback"),
        "the trailing-slash root must not escape to application fallback"
    );
    let expired = request(running.address(), "GET", "/slow").await;
    assert!(expired.starts_with("HTTP/1.1 503"), "{expired}");
    assert!(expired.contains("deadline_exceeded"), "{expired}");
    assert_health(
        &request(running.address(), "GET", PATHS[2]).await,
        200,
        "UP",
        false,
    );
    running.shutdown().await.expect("settled");
}
