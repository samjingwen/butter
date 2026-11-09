//! Real loopback acceptance for the public web-security boundary.
#![cfg(feature = "security-web")]

use butter_actuator::Actuator;
use butter_boot::Application;
use butter_security::{
    Assurance, AssuranceLevel, Authentication, AuthenticationFailure, AuthenticationFuture,
    AuthenticationManager, AuthenticationMechanism, AuthenticationRequest, Authority,
    AuthorityRequired, AuthorizationDecision, AuthorizationFuture, AuthorizationManager,
    AuthorizationOperationalError, CredentialRequest, NamedPrincipal, PermitAll, Principal,
    SecurityContext, SubjectId,
};
use butter_security_web::{
    AccessDeniedHandler, AllRequestMatcher, AuthenticationEntryPoint, BearerToken,
    BearerTokenExtractor, CredentialExtraction, CredentialExtractionFailure, CredentialExtractor,
    CredentialLimit, CredentialSource, ExactPathMatcher, HostMatcher, NeutralAccessDeniedHandler,
    NeutralAuthenticationEntryPoint, PathPrefixMatcher, RequestMatcher, RequestMetadata,
    SecurityChain, SecurityComponentId, SecurityWeb, UnmatchedPolicy,
};
use butter_web::{
    ResponseConstructionBudget, Router,
    native::{Extension, http::HeaderValue},
    routing::get,
};
use std::{
    error::Error,
    future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

type TestError = Box<dyn Error + Send + Sync>;
type TestResult = Result<(), TestError>;

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

async fn request(address: SocketAddr, path: &str, headers: &[(&str, &str)]) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect to owned listener");
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n"
        );
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
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

fn authentication(subject: &str, authorities: &[&str]) -> Result<Authentication, TestError> {
    let principal: Arc<dyn Principal> =
        Arc::new(NamedPrincipal::new(SubjectId::new(subject)?, None));
    let mut builder = Authentication::builder(
        principal,
        AuthenticationMechanism::new("synthetic")?,
        SystemTime::UNIX_EPOCH,
        Assurance::new(AssuranceLevel::SINGLE_FACTOR),
    );
    for authority in authorities {
        builder.authority(Authority::new(*authority)?)?;
    }
    Ok(builder.build())
}

struct SyntheticManager;

impl AuthenticationManager for SyntheticManager {
    fn authenticate<'a>(
        &'a self,
        request: &'a dyn AuthenticationRequest,
    ) -> AuthenticationFuture<'a> {
        let outcome = request
            .downcast_ref::<CredentialRequest<BearerToken>>()
            .map(|request| request.credential().expose_secret())
            .map(|token| match token {
                b"reader-token" => authentication("reader", &["records.read"]),
                b"admin-token" => authentication("admin", &["records.read", "records.admin"]),
                _ => Err("invalid".into()),
            });
        Box::pin(async move {
            match outcome {
                Some(Ok(authentication)) => Ok(authentication),
                Some(Err(_)) => Err(AuthenticationFailure::Rejected(
                    butter_security::AuthenticationRejection::InvalidCredentials,
                )),
                None => Err(AuthenticationFailure::UnsupportedMechanism),
            }
        })
    }
}

struct ApiKeyExtractor {
    mechanism: AuthenticationMechanism,
}

impl CredentialExtractor for ApiKeyExtractor {
    fn extract(
        &self,
        source: CredentialSource<'_>,
    ) -> Result<CredentialExtraction, CredentialExtractionFailure> {
        let Some(value) = source.headers().get("x-api-key") else {
            return Ok(CredentialExtraction::Missing);
        };
        let value = value
            .to_str()
            .map_err(|_| CredentialExtractionFailure::Malformed)?;
        Ok(CredentialExtraction::Present(Box::new(
            CredentialRequest::new(self.mechanism.clone(), value.to_owned()),
        )))
    }
}

fn handlers() -> (
    Arc<dyn AuthenticationEntryPoint>,
    Arc<dyn AccessDeniedHandler>,
) {
    (
        Arc::new(NeutralAuthenticationEntryPoint::bearer()),
        Arc::new(NeutralAccessDeniedHandler),
    )
}

fn public_chain(
    id: &str,
    priority: u16,
    matcher: Arc<dyn RequestMatcher>,
) -> Result<SecurityChain, TestError> {
    let mut chain = SecurityChain::builder(SecurityComponentId::new(id)?, priority, matcher);
    chain.authorization_manager(Arc::new(PermitAll));
    chain.neutral_handlers();
    Ok(chain.build()?)
}

fn authenticated_chain(
    id: &str,
    priority: u16,
    matcher: Arc<dyn RequestMatcher>,
    required: &str,
) -> Result<SecurityChain, TestError> {
    let mut chain = SecurityChain::builder(SecurityComponentId::new(id)?, priority, matcher);
    chain.credential_extractor(
        SecurityComponentId::new("bearer")?,
        Arc::new(BearerTokenExtractor::new(
            AuthenticationMechanism::new("bearer")?,
            CredentialLimit::new(64)?,
        )),
    )?;
    chain.credential_extractor(
        SecurityComponentId::new("api-key")?,
        Arc::new(ApiKeyExtractor {
            mechanism: AuthenticationMechanism::new("api-key")?,
        }),
    )?;
    chain.authentication_manager(Arc::new(SyntheticManager));
    chain.authorization_manager(Arc::new(AuthorityRequired::new(Authority::new(required)?)));
    let (entry_point, denied_handler) = handlers();
    chain.authentication_entry_point(entry_point);
    chain.access_denied_handler(denied_handler);
    Ok(chain.build()?)
}

fn security() -> Result<SecurityWeb, TestError> {
    let mut security = SecurityWeb::builder();
    security.chain(public_chain(
        "public",
        10,
        Arc::new(ExactPathMatcher::new("/public")?),
    )?)?;
    security.chain(authenticated_chain(
        "admin",
        20,
        Arc::new(ExactPathMatcher::new("/api/admin")?),
        "records.admin",
    )?)?;
    security.chain(authenticated_chain(
        "api",
        30,
        Arc::new(PathPrefixMatcher::new("/api")?),
        "records.read",
    )?)?;
    security.chain(public_chain(
        "direct-host",
        40,
        Arc::new(AllRequestMatcher::new(vec![
            Arc::new(ExactPathMatcher::new("/host")?),
            Arc::new(HostMatcher::new("localhost")?),
        ])?),
    )?)?;
    security.unmatched_policy(UnmatchedPolicy::Deny);
    Ok(security.build()?)
}

fn subject(context: &SecurityContext) -> &str {
    context
        .principal()
        .map_or("anonymous", |principal| principal.subject().as_str())
}

#[tokio::test]
async fn first_match_authentication_denial_ambiguity_isolation_and_shutdown() -> TestResult {
    let routes = Router::new()
        .route(
            "/public",
            get(
                |Extension(context): Extension<SecurityContext>| async move {
                    subject(&context).to_owned()
                },
            ),
        )
        .route(
            "/api/who",
            get(
                |Extension(context): Extension<SecurityContext>| async move {
                    subject(&context).to_owned()
                },
            ),
        )
        .route("/api/admin", get(|| async { "admin-area" }))
        .route("/host", get(|| async { "direct-host" }))
        .route("/outside", get(|| async { "must-not-run" }));
    let running = Application::new(routes)
        .bind(loopback())
        .security(security()?)?
        .start()
        .await?;
    let address = running.address();

    let public = request(address, "/public", &[]).await;
    assert!(public.starts_with("HTTP/1.1 200"), "{public}");
    assert!(public.ends_with("anonymous"), "{public}");

    let missing = request(address, "/api/who", &[]).await;
    assert!(missing.starts_with("HTTP/1.1 401"), "{missing}");
    assert!(
        missing
            .to_ascii_lowercase()
            .contains("www-authenticate: bearer"),
        "{missing}"
    );
    assert!(
        missing
            .to_ascii_lowercase()
            .contains("cache-control: no-store")
    );

    let invalid = request(
        address,
        "/api/who",
        &[("Authorization", "Bearer private-invalid-token")],
    )
    .await;
    assert!(invalid.starts_with("HTTP/1.1 401"), "{invalid}");
    assert!(!invalid.contains("private-invalid-token"), "{invalid}");

    let malformed = request(
        address,
        "/api/who",
        &[("Authorization", "Bearer  reader-token")],
    )
    .await;
    assert!(malformed.starts_with("HTTP/1.1 400"), "{malformed}");

    let duplicate = request(
        address,
        "/api/who",
        &[
            ("Authorization", "Bearer reader-token"),
            ("Authorization", "Bearer admin-token"),
        ],
    )
    .await;
    assert!(duplicate.starts_with("HTTP/1.1 400"), "{duplicate}");

    let conflicting = request(
        address,
        "/api/who",
        &[
            ("Authorization", "Bearer reader-token"),
            ("x-api-key", "private-api-key"),
        ],
    )
    .await;
    assert!(conflicting.starts_with("HTTP/1.1 400"), "{conflicting}");
    assert!(!conflicting.contains("private-api-key"), "{conflicting}");

    let denied = request(
        address,
        "/api/admin",
        &[("Authorization", "Bearer reader-token")],
    )
    .await;
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");
    let admin = request(
        address,
        "/api/admin",
        &[("Authorization", "Bearer admin-token")],
    )
    .await;
    assert!(admin.starts_with("HTTP/1.1 200"), "{admin}");
    assert!(admin.ends_with("admin-area"), "{admin}");

    let reader = request(
        address,
        "/api/who",
        &[("Authorization", "Bearer reader-token")],
    );
    let administrator = request(
        address,
        "/api/who",
        &[("Authorization", "Bearer admin-token")],
    );
    let (reader, administrator) = tokio::join!(reader, administrator);
    assert!(reader.ends_with("reader"), "{reader}");
    assert!(administrator.ends_with("admin"), "{administrator}");

    let forwarded = request(
        address,
        "/host",
        &[("x-forwarded-host", "attacker.example")],
    )
    .await;
    assert!(forwarded.ends_with("direct-host"), "{forwarded}");
    let encoded = request(address, "/api%2Fwho", &[]).await;
    assert!(encoded.starts_with("HTTP/1.1 404"), "{encoded}");
    let unmatched = request(address, "/outside", &[]).await;
    assert!(unmatched.starts_with("HTTP/1.1 404"), "{unmatched}");
    assert!(!unmatched.contains("must-not-run"), "{unmatched}");

    running.shutdown().await?;
    assert!(TcpStream::connect(address).await.is_err());
    Ok(())
}

#[tokio::test]
async fn security_stays_inside_admission_and_outside_actuator_reads() -> TestResult {
    let mut chain = SecurityChain::builder(
        SecurityComponentId::new("all-application")?,
        1,
        Arc::new(butter_security_web::AnyRequest),
    );
    chain.authorization_manager(Arc::new(AuthorityRequired::new(Authority::new(
        "application.access",
    )?)));
    chain.neutral_handlers();
    let mut security = SecurityWeb::builder();
    security.chain(chain.build()?)?;
    security.unmatched_policy(UnmatchedPolicy::Deny);
    let routes = Router::new().route("/application", get(|| async { "no" }));
    let running = Application::new(routes)
        .bind(loopback())
        .security(security.build()?)?
        .actuator(Actuator::builder().build())?
        .start()
        .await?;

    let application = request(running.address(), "/application", &[]).await;
    assert!(application.starts_with("HTTP/1.1 401"), "{application}");
    let health = request(running.address(), "/actuator/health", &[]).await;
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.ends_with(r#"{"status":"UP"}"#), "{health}");
    running.shutdown().await?;
    Ok(())
}

struct DropSignal(Arc<AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct PendingManager {
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl AuthenticationManager for PendingManager {
    fn authenticate<'a>(
        &'a self,
        _request: &'a dyn AuthenticationRequest,
    ) -> AuthenticationFuture<'a> {
        let started = Arc::clone(&self.started);
        let dropped = Arc::clone(&self.dropped);
        Box::pin(async move {
            let _signal = DropSignal(dropped);
            started.store(true, Ordering::SeqCst);
            future::pending::<Result<Authentication, AuthenticationFailure>>().await
        })
    }
}

#[tokio::test]
async fn outer_deadline_cancels_authentication_without_invoking_the_handler() -> TestResult {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let invoked = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&invoked);
    let mut chain = SecurityChain::builder(
        SecurityComponentId::new("pending")?,
        1,
        Arc::new(butter_security_web::AnyRequest),
    );
    chain.credential_extractor(
        SecurityComponentId::new("bearer")?,
        Arc::new(BearerTokenExtractor::new(
            AuthenticationMechanism::new("bearer")?,
            CredentialLimit::new(64)?,
        )),
    )?;
    chain.authentication_manager(Arc::new(PendingManager {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
    }));
    chain.authorization_manager(Arc::new(PermitAll));
    chain.neutral_handlers();
    let mut security = SecurityWeb::builder();
    security.chain(chain.build()?)?;
    security.unmatched_policy(UnmatchedPolicy::Deny);
    let routes = Router::new().route(
        "/work",
        get(move || {
            let observed = Arc::clone(&observed);
            async move {
                observed.store(true, Ordering::SeqCst);
                "must-not-run"
            }
        }),
    );
    let running = Application::new(routes)
        .bind(loopback())
        .security(security.build()?)?
        .request_budget(ResponseConstructionBudget::new(Duration::from_millis(20))?)
        .start()
        .await?;

    let expired = request(
        running.address(),
        "/work",
        &[("Authorization", "Bearer reader-token")],
    )
    .await;
    assert!(expired.starts_with("HTTP/1.1 503"), "{expired}");
    assert!(expired.contains("deadline_exceeded"), "{expired}");
    assert!(started.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!invoked.load(Ordering::SeqCst));
    running.shutdown().await?;
    Ok(())
}

struct PendingAuthorization {
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl AuthorizationManager<RequestMetadata> for PendingAuthorization {
    fn check<'a>(
        &'a self,
        _context: &'a SecurityContext,
        _request: &'a RequestMetadata,
    ) -> AuthorizationFuture<'a> {
        let started = Arc::clone(&self.started);
        let dropped = Arc::clone(&self.dropped);
        Box::pin(async move {
            let _signal = DropSignal(dropped);
            started.store(true, Ordering::SeqCst);
            future::pending::<Result<AuthorizationDecision, AuthorizationOperationalError>>().await
        })
    }
}

#[tokio::test]
async fn outer_deadline_cancels_authorization_without_invoking_the_handler() -> TestResult {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let invoked = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&invoked);
    let mut chain = SecurityChain::builder(
        SecurityComponentId::new("pending-authorization")?,
        1,
        Arc::new(butter_security_web::AnyRequest),
    );
    chain.authorization_manager(Arc::new(PendingAuthorization {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
    }));
    chain.neutral_handlers();
    let mut security = SecurityWeb::builder();
    security.chain(chain.build()?)?;
    security.unmatched_policy(UnmatchedPolicy::Deny);
    let routes = Router::new().route(
        "/work",
        get(move || {
            let observed = Arc::clone(&observed);
            async move {
                observed.store(true, Ordering::SeqCst);
                "must-not-run"
            }
        }),
    );
    let running = Application::new(routes)
        .bind(loopback())
        .security(security.build()?)?
        .request_budget(ResponseConstructionBudget::new(Duration::from_millis(20))?)
        .start()
        .await?;

    let expired = request(running.address(), "/work", &[]).await;
    assert!(expired.starts_with("HTTP/1.1 503"), "{expired}");
    assert!(expired.contains("deadline_exceeded"), "{expired}");
    assert!(started.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!invoked.load(Ordering::SeqCst));
    running.shutdown().await?;
    Ok(())
}

#[test]
fn challenge_values_are_validated_by_the_http_type() {
    assert!(HeaderValue::from_bytes(b"Bearer\r\nprivate: value").is_err());
}

#[test]
fn repeated_security_attachment_is_rejected_without_replacement() -> TestResult {
    let security = security()?;
    let application = Application::new(Router::new()).security(security.clone())?;
    assert!(application.security(security).is_err());
    Ok(())
}
