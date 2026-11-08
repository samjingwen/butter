//! Real loopback HTTP consumers of the public bootstrap and shutdown contract.

use butter_boot::Application;
use butter_web::{ResponseConstructionBudget, Router, routing::get};
use std::{net::SocketAddr, sync::Arc, time::Duration};
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
}
