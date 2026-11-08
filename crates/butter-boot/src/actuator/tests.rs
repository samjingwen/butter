//! Adapter seam tests keep the connector available while observing every lifecycle
//! state and deliberately stop polling a separate sampling runtime for freshness.
//! Public Application tests separately establish shared ownership and settlement.
use super::*;
use butter_actuator::{Actuator, ContributorGroup, ContributorId};
use butter_core::{
    cleanup::CleanupBudget,
    health::{HealthPolicy, HealthStatus},
    lifecycle::{ShutdownBudget, Supervisor},
};
use butter_web::{RequestPolicy, ResponseConstructionBudget, Router};
use std::{net::SocketAddr, sync::mpsc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
};

fn supervisor() -> Supervisor {
    let second = Duration::from_secs(1);
    Supervisor::new(
        ShutdownBudget::new(
            second,
            second,
            second,
            CleanupBudget::new(second, second, second).expect("cleanup"),
        )
        .expect("shutdown"),
    )
}
async fn request(address: SocketAddr, method: &str, path: &str) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address).await.expect("owned connector");
        stream
            .write_all(
                format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("send");
        let mut response = String::new();
        stream.read_to_string(&mut response).await.expect("read");
        response
    })
    .await
    .expect("bounded HTTP")
}
async fn assert_views(address: SocketAddr, overall: bool, live: bool, ready: bool) {
    for (path, up) in [
        ("/actuator/health", overall),
        ("/actuator/health/liveness", live),
        ("/actuator/health/readiness", ready),
    ] {
        for method in ["GET", "HEAD"] {
            let response = request(address, method, path).await;
            assert!(
                response.starts_with(if up { "HTTP/1.1 200" } else { "HTTP/1.1 503" }),
                "{path}: {response}"
            );
            let body = response.split_once("\r\n\r\n").expect("HTTP").1;
            assert_eq!(
                body,
                if method == "HEAD" {
                    ""
                } else if up {
                    r#"{"status":"UP"}"#
                } else {
                    r#"{"status":"DOWN"}"#
                }
            );
        }
    }
}

struct Sampler {
    stop: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Sampler {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("sampling runtime joined");
        }
    }
}

#[tokio::test]
async fn loopback_freshness_writer_stop_and_full_lifecycle_matrix() {
    let mut application = supervisor();
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let released = release.clone();
    application
        .register("application", move |startup| async move {
            let running = startup.acknowledge_started();
            running.signal().draining().await;
            released.notified().await;
            Ok(running.stopped())
        })
        .expect("application component");
    let lifecycle = application.status();
    let application = application.start_unapproved();
    let (published, receive) = oneshot::channel();
    let (stop, wait_stop) = mpsc::channel();
    let (stopped, receive_stopped) = oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("sampler runtime");
        let (running, diagnostics) = runtime.block_on(async {
            let mut builder = Actuator::builder();
            let policy = HealthPolicy::new(
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(100),
                Duration::from_millis(1),
            )
            .expect("health policy");
            let diagnostics = builder
                .probe(
                    ContributorId::new("sample").expect("id"),
                    ContributorGroup::Readiness,
                    policy,
                    || async { Ok::<_, ()>(()) },
                )
                .expect("probe");
            let mut base = supervisor();
            let view = builder
                .build()
                .register_in(&mut base, lifecycle)
                .expect("register");
            let running = base.start();
            running.status().wait_ready().await.expect("sampler ready");
            while diagnostics.snapshot().status() != HealthStatus::Healthy {
                tokio::task::yield_now().await;
            }
            let expires = diagnostics
                .snapshot()
                .last_probe()
                .expect("probe")
                .completed_at()
                + policy.maximum_age();
            published
                .send((view, diagnostics.clone(), expires))
                .expect("publish view");
            (running, diagnostics)
        });
        // No runtime polling occurs until released. The sole writer is still alive.
        let _ = wait_stop.recv();
        runtime
            .block_on(running.shutdown_checked())
            .expect("settle sampler");
        assert_eq!(diagnostics.snapshot().status(), HealthStatus::Stopped);
        let _ = stopped.send(());
    });
    let mut sampler = Sampler {
        stop,
        thread: Some(thread),
    };
    let (view, diagnostics, expires) = receive.await.expect("sampler view");
    let mut connector = supervisor();
    let budget = ResponseConstructionBudget::new(Duration::from_secs(1)).expect("budget");
    let http = routes(view)
        .expect("adapter")
        .assemble(
            RequestPolicy::new(connector.operation_admission(), budget),
            Router::new(),
        )
        .await
        .expect("boundary");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    http.register_in(&mut connector, "http", listener)
        .expect("connector registration");
    let connector = connector.start();
    connector.status().wait_ready().await.expect("HTTP ready");
    assert_views(address, false, true, false).await; // Starting
    let application = application.approve_readiness();
    application
        .status()
        .wait_ready()
        .await
        .expect("application ready");
    // Fresh success is separately exercised over HTTP by the public API tests.
    tokio::time::sleep_until(expires).await;
    assert_eq!(diagnostics.snapshot().status(), HealthStatus::Stale);
    assert_views(address, false, true, false).await;
    sampler
        .stop
        .send(())
        .expect("stop writer while lifecycle stays ready");
    receive_stopped.await.expect("writer stopped");
    sampler
        .thread
        .take()
        .expect("worker")
        .join()
        .expect("worker joined");
    assert_views(address, false, true, false).await;
    application.handle().request();
    assert_views(address, false, true, false).await; // Draining
    release.notify_one();
    application
        .shutdown_checked()
        .await
        .expect("application stopped");
    assert_views(address, false, false, false).await; // Stopped
    connector
        .shutdown_checked()
        .await
        .expect("connector released");
    assert!(TcpStream::connect(address).await.is_err());
}
