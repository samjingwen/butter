//! Real loopback HTTP consumers of the public bootstrap and shutdown contract.

use butter_boot::Application;
use butter_web::{ResponseConstructionBudget, Router, routing::get};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

async fn request(address: SocketAddr, path: &str) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect to owned listener");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("send request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");
        response
    })
    .await
    .expect("bounded loopback exchange")
}

#[tokio::test]
async fn start_serves_application_without_implicit_probes_then_shutdown_releases_the_listener() {
    let running = Application::new(Router::new().route("/", get(|| async { "hello butter" })))
        .bind(loopback())
        .start()
        .await
        .expect("start application");
    let address = running.address();
    for path in ["/"] {
        let response = request(address, path).await;
        assert!(response.starts_with("HTTP/1.1 200"), "{path}: {response}");
        if path == "/" {
            assert!(response.ends_with("hello butter"));
        }
    }
    for path in [
        "/live",
        "/ready",
        "/actuator/health",
        "/actuator/health/liveness",
        "/actuator/health/readiness",
    ] {
        assert!(
            request(address, path).await.starts_with("HTTP/1.1 404"),
            "{path}"
        );
    }
    running.shutdown().await.expect("checked shutdown");
    assert!(
        TcpStream::connect(address).await.is_err(),
        "listener closed before shutdown completes"
    );
}

#[tokio::test]
async fn cancelling_a_borrowed_wait_does_not_stop_the_application() {
    let running = Application::new(Router::new().route("/", get(|| async { "alive" })))
        .bind(loopback())
        .start()
        .await
        .expect("start");
    assert!(
        tokio::time::timeout(Duration::from_millis(10), running.wait())
            .await
            .is_err()
    );
    assert!(
        request(running.address(), "/")
            .await
            .starts_with("HTTP/1.1 200")
    );
    running
        .shutdown()
        .await
        .expect("shutdown after cancelled waiter");
}

#[tokio::test]
async fn dropping_the_owner_requests_drain_and_the_observer_retains_completion() {
    let running = Application::new(Router::new())
        .bind(loopback())
        .start()
        .await
        .expect("start");
    let address = running.address();
    let observer = running.observer();
    drop(running);
    tokio::time::timeout(Duration::from_secs(5), observer.wait_checked())
        .await
        .expect("bounded driver settlement")
        .expect("checked completion after owner drop");
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn startup_refuses_foreign_ports_and_legacy_paths_are_ordinary_application_routes() {
    let foreign = tokio::net::TcpListener::bind(loopback())
        .await
        .expect("own blocker");
    let address = foreign.local_addr().expect("blocker address");
    assert!(
        Application::new(Router::new())
            .bind(address)
            .start()
            .await
            .is_err()
    );
    assert_eq!(foreign.local_addr().expect("blocker remains open"), address);
    for path in ["/live", "/ready"] {
        let result =
            Application::new(Router::new().route(path, get(|| async { "application route" })))
                .bind(loopback())
                .start()
                .await;
        let running = result.expect("legacy paths are no longer reserved");
        assert!(
            request(running.address(), path)
                .await
                .ends_with("application route")
        );
        running.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn protected_initializers_run_before_bind_and_roll_back_in_lifo_order() {
    let foreign = tokio::net::TcpListener::bind(loopback())
        .await
        .expect("own blocker");
    let address = foreign.local_addr().expect("blocker address");
    let events = Arc::new(Mutex::new(Vec::new()));
    let first = events.clone();
    let second = events.clone();

    let result = Application::new(Router::new())
        .initialize(move |scope| {
            Box::pin(async move {
                first.lock().expect("events").push("initialize.first");
                let slot = scope.reserve_cleanup("resource.first")?;
                slot.register(move || async move {
                    first.lock().expect("events").push("cleanup.first");
                    Ok(())
                });
                Ok(())
            })
        })
        .initialize(move |scope| {
            Box::pin(async move {
                second.lock().expect("events").push("initialize.second");
                let slot = scope.reserve_cleanup("resource.second")?;
                slot.register(move || async move {
                    second.lock().expect("events").push("cleanup.second");
                    Ok(())
                });
                Ok(())
            })
        })
        .bind(address)
        .start()
        .await;

    assert!(result.is_err(), "occupied listener must reject startup");
    assert_eq!(
        *events.lock().expect("events"),
        [
            "initialize.first",
            "initialize.second",
            "cleanup.second",
            "cleanup.first",
        ]
    );
    assert_eq!(foreign.local_addr().expect("blocker remains open"), address);
}

#[tokio::test]
async fn initializer_failure_rolls_back_registered_resources_without_binding() {
    let probe = tokio::net::TcpListener::bind(loopback())
        .await
        .expect("select address");
    let address = probe.local_addr().expect("probe address");
    drop(probe);
    let cleaned = Arc::new(AtomicBool::new(false));
    let cleanup = cleaned.clone();

    let result = Application::new(Router::new())
        .initialize(move |scope| {
            Box::pin(async move {
                let slot = scope.reserve_cleanup("resource")?;
                slot.register(move || async move {
                    cleanup.store(true, Ordering::SeqCst);
                    Ok(())
                });
                Err(std::io::Error::other("synthetic initialization failure").into())
            })
        })
        .bind(address)
        .start()
        .await;

    assert!(result.is_err(), "initializer failure must propagate");
    assert!(cleaned.load(Ordering::SeqCst), "resource must be closed");
    let rebound = tokio::net::TcpListener::bind(address)
        .await
        .expect("initializer failed before listener binding");
    drop(rebound);
}

#[tokio::test]
async fn checked_shutdown_propagates_initializer_cleanup_failure() {
    let running = Application::new(Router::new())
        .initialize(|scope| {
            Box::pin(async move {
                scope.reserve_cleanup("resource")?.register(|| async {
                    Err(std::io::Error::other("synthetic cleanup failure").into())
                });
                Ok(())
            })
        })
        .bind(loopback())
        .start()
        .await
        .expect("start");

    assert!(
        running.shutdown().await.is_err(),
        "checked shutdown must retain cleanup failure"
    );
}

#[tokio::test]
async fn initializer_cleanup_is_bounded_by_the_application_policy() {
    let entered = Arc::new(AtomicBool::new(false));
    let cleanup = entered.clone();
    let running = Application::new(Router::new())
        .initialize(move |scope| {
            Box::pin(async move {
                scope
                    .reserve_cleanup("resource")?
                    .register(move || async move {
                        cleanup.store(true, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                        Ok(())
                    });
                Ok(())
            })
        })
        .bind(loopback())
        .start()
        .await
        .expect("start");

    let result = tokio::time::timeout(Duration::from_secs(7), running.shutdown())
        .await
        .expect("cleanup policy must bound a non-terminating hook");
    assert!(entered.load(Ordering::SeqCst), "cleanup hook must start");
    assert!(result.is_err(), "timed-out cleanup must fail shutdown");
}

#[tokio::test]
async fn request_construction_deadline_is_enforced_by_the_protected_boundary() {
    let router = Router::new().route("/", get(|| async { "healthy" })).route(
        "/slow",
        get(|| async {
            std::future::pending::<()>().await;
            "unreachable"
        }),
    );
    let budget = ResponseConstructionBudget::new(Duration::from_millis(20)).expect("valid budget");
    let running = Application::new(router)
        .bind(loopback())
        .request_budget(budget)
        .start()
        .await
        .expect("start");
    let response = request(running.address(), "/slow").await;
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(
        response.contains("\"code\":\"deadline_exceeded\""),
        "{response}"
    );
    assert!(
        request(running.address(), "/")
            .await
            .starts_with("HTTP/1.1 200")
    );
    running.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn graceful_shutdown_waits_for_an_already_admitted_request() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (started, gate) = (entered.clone(), release.clone());
    let cleaned = Arc::new(AtomicBool::new(false));
    let cleanup = cleaned.clone();
    let router = Router::new().route(
        "/work",
        get(move || {
            let (started, gate) = (started.clone(), gate.clone());
            async move {
                started.notify_one();
                gate.notified().await;
                "settled"
            }
        }),
    );
    let running = Application::new(router)
        .initialize(move |scope| {
            Box::pin(async move {
                scope
                    .reserve_cleanup("resource")?
                    .register(move || async move {
                        cleanup.store(true, Ordering::SeqCst);
                        Ok(())
                    });
                Ok(())
            })
        })
        .bind(loopback())
        .start()
        .await
        .expect("start");
    let address = running.address();
    let request_task = tokio::spawn(async move { request(address, "/work").await });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("handler admitted");
    let status = running.status();
    let mut shutdown = Box::pin(running.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut shutdown)
            .await
            .is_err(),
        "shutdown must wait for admitted work"
    );
    assert!(
        status.is_draining(),
        "drain started while the handler is held"
    );
    assert!(
        !cleaned.load(Ordering::SeqCst),
        "resource cleanup must wait for admitted work"
    );
    release.notify_one();
    assert!(
        request_task
            .await
            .expect("join request")
            .ends_with("settled")
    );
    shutdown
        .await
        .expect("checked drain after request completes");
    assert!(cleaned.load(Ordering::SeqCst));
}
