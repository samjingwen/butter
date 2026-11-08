//! Tracing is captured locally, never installed as a global subscriber.
#![cfg(feature = "actuator")]

use butter_actuator::Actuator;
use butter_boot::Application;
use butter_web::{AdmittedRequest, Router, routing::get};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

#[derive(Default, Clone, Debug)]
struct Fields(BTreeMap<String, String>);
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
}
#[derive(Default, Clone)]
struct Capture {
    next: Arc<AtomicU64>,
    spans: Arc<Mutex<Vec<Fields>>>,
    events: Arc<Mutex<Vec<Fields>>>,
}
impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        if attrs.metadata().name() == "batter.http" {
            let mut fields = Fields::default();
            attrs.record(&mut fields);
            self.spans.lock().expect("capture").push(fields);
        }
        Id::from_u64(self.next.fetch_add(1, Ordering::SeqCst) + 1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() == "batter"
            && event.metadata().fields().field("route").is_some()
        {
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.events.lock().expect("capture").push(fields);
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[test]
fn attachment_preserves_application_templates_single_completion_and_correlation() {
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime").block_on(async {
            let routes = Router::new()
                .route("/items/{id}", get(|request: AdmittedRequest| async move { request.correlation_id().as_str().to_owned() }))
                .route("/slow/{id}", get(|| async { std::future::pending::<String>().await }));
            let running = Application::new(routes).bind("127.0.0.1:0".parse().expect("address"))
                .request_budget(butter_web::ResponseConstructionBudget::new(Duration::from_millis(20)).expect("budget"))
                .actuator(Actuator::builder().build()).expect("attach").start().await.expect("start");
            for (method, path, expected_route) in [("GET", "/items/123", "/items/{id}"), ("GET", "/slow/456", "/slow/{id}"),
                ("GET", "/actuator/health", "/actuator/health"), ("HEAD", "/actuator/health", "/actuator/health"),
                ("POST", "/actuator/health", "/actuator/health"), ("GET", "/actuator/", "/actuator/"),
                ("GET", "/actuator/unknown", "/actuator/{*public_read_path}")] {
                let response = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut stream = TcpStream::connect(running.address()).await.expect("owned listener");
                    stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nx-request-id: untrusted-client-marker\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.expect("send");
                    let mut response = String::new();
                    stream.read_to_string(&mut response).await.expect("response");
                    response
                }).await.expect("bounded HTTP");
                let events = std::mem::take(&mut *capture.events.lock().expect("events"));
                assert_eq!(events.len(), 1, "exactly one completion for {path}: {events:?}");
                let event = &events[0].0;
                assert_eq!(event.get("route").map(String::as_str), Some(expected_route));
                let spans = std::mem::take(&mut *capture.spans.lock().expect("spans"));
                assert_eq!(spans.len(), 1, "one HTTP span for {path}: {spans:?}");
                assert_eq!(spans[0].0.get("route").map(String::as_str), Some(expected_route));
                let correlation = response.lines().find_map(|line| line.strip_prefix("x-request-id: ")).expect("response identity").trim();
                assert_ne!(correlation, "untrusted-client-marker");
                assert_eq!(event.get("request_id").map(String::as_str), Some(correlation));
                if path.starts_with("/items/") {
                    assert_eq!(response.split_once("\r\n\r\n").expect("body").1, correlation);
                }
            }
            running.shutdown().await.expect("settled");
        });
    });
}
