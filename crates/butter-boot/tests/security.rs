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
    BearerTokenExtractor, BrowserCookie, BrowserOrigin, CookieHeaderPolicy, CookieLifetime,
    CookieName, CookieVisibility, CredentialExtraction, CredentialExtractionFailure,
    CredentialExtractor, CredentialLimit, CredentialSource, CsrfOperationError, CsrfProtection,
    CsrfToken, CsrfTokenFuture, CsrfTokenLoad, CsrfTokenLoadFuture, CsrfTokenRepository,
    CsrfWriteFuture, ExactPathMatcher, HostMatcher, NeutralAccessDeniedHandler,
    NeutralAuthenticationEntryPoint, OriginPolicy, PathPrefixMatcher, RefererFallback,
    RequestMatcher, RequestMetadata, SameSite, SecurityChain, SecurityComponentId,
    SecurityContextLoad, SecurityContextLoadFuture, SecurityContextRepository, SecurityWeb,
    SessionAuthenticationStrategy, SessionCookie, SessionIdentifier, SessionOperationError,
    SessionRotationFuture, SessionTransition, SessionWriteFuture, SpaCsrfTokenRequestHandler,
    StatefulSecurity, UnmatchedPolicy,
};
use butter_web::{
    ResponseConstructionBudget, Router,
    native::{
        Extension,
        http::{HeaderName, HeaderValue, StatusCode, header},
        response::IntoResponse,
    },
    routing::{get, post},
};
use std::{
    collections::HashMap,
    error::Error,
    future,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
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
    http_request(address, "GET", path, headers, "").await
}

async fn http_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("connect to owned listener");
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        request.push_str(body);
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

#[derive(Default)]
struct BrowserState {
    sessions: Mutex<HashMap<String, SecurityContext>>,
    csrf_tokens: Mutex<HashMap<String, String>>,
    session_sequence: AtomicUsize,
    csrf_sequence: AtomicUsize,
    save_mode: AtomicU8,
}

impl BrowserState {
    fn with_unconfirmed_saves() -> Self {
        Self {
            save_mode: AtomicU8::new(1),
            ..Self::default()
        }
    }

    fn session_count(&self) -> usize {
        self.sessions.lock().expect("session fixture lock").len()
    }
}

impl SecurityContextRepository for BrowserState {
    fn load<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        identifier: &'a SessionIdentifier,
    ) -> SecurityContextLoadFuture<'a> {
        let result = self
            .sessions
            .lock()
            .map_err(|_| SessionOperationError::Internal)
            .map(|sessions| {
                sessions
                    .get(identifier.expose_secret())
                    .cloned()
                    .map_or(SecurityContextLoad::Missing, SecurityContextLoad::Active)
            });
        Box::pin(async move { result })
    }

    fn save<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        previous: Option<&'a SessionIdentifier>,
        identifier: &'a SessionIdentifier,
        context: &'a SecurityContext,
    ) -> SessionWriteFuture<'a> {
        let result = self
            .sessions
            .lock()
            .map_err(|_| SessionOperationError::Internal)
            .and_then(|mut sessions| {
                if let Some(previous) = previous {
                    sessions.remove(previous.expose_secret());
                }
                sessions.insert(identifier.expose_secret().to_owned(), context.clone());
                if self.save_mode.load(Ordering::SeqCst) == 1 {
                    Err(SessionOperationError::Unconfirmed)
                } else {
                    Ok(())
                }
            });
        Box::pin(async move { result })
    }

    fn invalidate<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        identifier: &'a SessionIdentifier,
    ) -> SessionWriteFuture<'a> {
        let result = self
            .sessions
            .lock()
            .map_err(|_| SessionOperationError::Internal)
            .map(|mut sessions| {
                sessions.remove(identifier.expose_secret());
            });
        Box::pin(async move { result })
    }
}

impl SessionAuthenticationStrategy for BrowserState {
    fn rotate<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        _previous: Option<&'a SessionIdentifier>,
        _context: &'a SecurityContext,
    ) -> SessionRotationFuture<'a> {
        let sequence = self.session_sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let result = SessionIdentifier::new(format!("session-{sequence}"))
            .map_err(|_| SessionOperationError::Internal);
        Box::pin(async move { result })
    }
}

struct NonRotatingStrategy;

impl SessionAuthenticationStrategy for NonRotatingStrategy {
    fn rotate<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        previous: Option<&'a SessionIdentifier>,
        _context: &'a SecurityContext,
    ) -> SessionRotationFuture<'a> {
        let value = previous.map_or("fixed-session", SessionIdentifier::expose_secret);
        let result =
            SessionIdentifier::new(value.to_owned()).map_err(|_| SessionOperationError::Internal);
        Box::pin(async move { result })
    }
}

impl CsrfTokenRepository for BrowserState {
    fn load<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        session: &'a SessionIdentifier,
    ) -> CsrfTokenLoadFuture<'a> {
        let result = self
            .csrf_tokens
            .lock()
            .map_err(|_| CsrfOperationError::Internal)
            .and_then(|tokens| {
                tokens
                    .get(session.expose_secret())
                    .map_or(Ok(CsrfTokenLoad::Missing), |token| {
                        CsrfToken::new(token.clone())
                            .map(CsrfTokenLoad::Found)
                            .map_err(|_| CsrfOperationError::Internal)
                    })
            });
        Box::pin(async move { result })
    }

    fn create<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        session: &'a SessionIdentifier,
    ) -> CsrfTokenFuture<'a> {
        let sequence = self.csrf_sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let value = format!("csrf-{sequence}");
        let result = self
            .csrf_tokens
            .lock()
            .map_err(|_| CsrfOperationError::Internal)
            .and_then(|mut tokens| {
                tokens.insert(session.expose_secret().to_owned(), value.clone());
                CsrfToken::new(value).map_err(|_| CsrfOperationError::Internal)
            });
        Box::pin(async move { result })
    }

    fn rotate<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        previous: &'a SessionIdentifier,
        session: &'a SessionIdentifier,
    ) -> CsrfTokenFuture<'a> {
        let sequence = self.csrf_sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let value = format!("csrf-{sequence}");
        let result = self
            .csrf_tokens
            .lock()
            .map_err(|_| CsrfOperationError::Internal)
            .and_then(|mut tokens| {
                tokens.remove(previous.expose_secret());
                tokens.insert(session.expose_secret().to_owned(), value.clone());
                CsrfToken::new(value).map_err(|_| CsrfOperationError::Internal)
            });
        Box::pin(async move { result })
    }

    fn invalidate<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        session: &'a SessionIdentifier,
    ) -> CsrfWriteFuture<'a> {
        let result = self
            .csrf_tokens
            .lock()
            .map_err(|_| CsrfOperationError::Internal)
            .map(|mut tokens| {
                tokens.remove(session.expose_secret());
            });
        Box::pin(async move { result })
    }
}

struct BrowserAuthorization;

impl AuthorizationManager<RequestMetadata> for BrowserAuthorization {
    fn check<'a>(
        &'a self,
        context: &'a SecurityContext,
        request: &'a RequestMetadata,
    ) -> AuthorizationFuture<'a> {
        let decision = if matches!(request.path(), "/login" | "/conflict-login")
            || context.is_authenticated()
        {
            AuthorizationDecision::Grant
        } else {
            AuthorizationDecision::Deny
        };
        Box::pin(async move { Ok(decision) })
    }
}

fn browser_security(state: Arc<BrowserState>) -> Result<SecurityWeb, TestError> {
    let strategy = Arc::clone(&state) as Arc<dyn SessionAuthenticationStrategy>;
    browser_security_with_strategy(state, strategy)
}

fn browser_security_with_strategy(
    state: Arc<BrowserState>,
    strategy: Arc<dyn SessionAuthenticationStrategy>,
) -> Result<SecurityWeb, TestError> {
    let origin = BrowserOrigin::loopback_http("http://localhost")?;
    let session_transport = BrowserCookie::new(
        &origin,
        CookieName::new("local_session")?,
        SameSite::Lax,
        CookieVisibility::HttpOnly,
    )?;
    let session_cookie = SessionCookie::new(
        session_transport,
        CookieLifetime::Session,
        CookieHeaderPolicy::TargetOnly,
    )?;
    let csrf_transport = BrowserCookie::new(
        &origin,
        CookieName::new("XSRF-TOKEN")?,
        SameSite::Lax,
        CookieVisibility::ScriptReadable,
    )?;
    let csrf_handler = SpaCsrfTokenRequestHandler::new(
        HeaderName::from_static("x-xsrf-token"),
        csrf_transport,
        CookieLifetime::Session,
    )?;
    let mut csrf = CsrfProtection::builder();
    csrf.token_repository(Arc::clone(&state) as Arc<dyn CsrfTokenRepository>);
    csrf.request_handler(Arc::new(csrf_handler));
    csrf.origin_policy(OriginPolicy::new(vec![origin], RefererFallback::Disabled)?);
    csrf.standard_request_protection();
    let mut stateful = StatefulSecurity::builder();
    stateful.context_repository(Arc::clone(&state) as Arc<dyn SecurityContextRepository>);
    stateful.session_authentication_strategy(strategy);
    stateful.session_cookie(session_cookie);
    stateful.csrf_protection(csrf.build()?);

    let mut chain = SecurityChain::builder(
        SecurityComponentId::new("browser")?,
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
    chain.authentication_manager(Arc::new(SyntheticManager));
    chain.authorization_manager(Arc::new(BrowserAuthorization));
    chain.neutral_handlers();
    chain.stateful_security(stateful.build()?);
    let mut security = SecurityWeb::builder();
    security.chain(chain.build()?)?;
    security.unmatched_policy(UnmatchedPolicy::Deny);
    Ok(security.build()?)
}

fn response_cookie(response: &str, expected_name: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("set-cookie") {
            return None;
        }
        let pair = value.trim().split(';').next()?;
        let (cookie_name, cookie_value) = pair.split_once('=')?;
        (cookie_name == expected_name).then(|| cookie_value.to_owned())
    })
}

fn has_set_cookie(response: &str) -> bool {
    response
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
}

#[tokio::test]
async fn stateful_browser_login_mutation_refresh_logout_and_replay_are_ordered() -> TestResult {
    let state = Arc::new(BrowserState::default());
    let login_authentication = authentication("browser-user", &["records.write"])?;
    let conflict_authentication = login_authentication.clone();
    let routes = Router::new()
        .route(
            "/login",
            post(move || {
                let authentication = login_authentication.clone();
                async move {
                    (
                        Extension(SessionTransition::establish(authentication)),
                        "logged-in",
                    )
                }
            }),
        )
        .route(
            "/who",
            get(
                |Extension(context): Extension<SecurityContext>| async move {
                    subject(&context).to_owned()
                },
            ),
        )
        .route("/mutate", post(|| async { "mutated" }))
        .route(
            "/csrf",
            get(|| async { (Extension(SessionTransition::expose_csrf()), "csrf") }),
        )
        .route(
            "/refresh",
            post(|| async { (Extension(SessionTransition::refresh()), "refreshed") }),
        )
        .route(
            "/logout",
            post(|| async { (Extension(SessionTransition::logout()), "logged-out") }),
        )
        .route(
            "/conflict-login",
            post(move || {
                let authentication = conflict_authentication.clone();
                async move {
                    let mut response = (StatusCode::OK, "conflict").into_response();
                    response
                        .extensions_mut()
                        .insert(SessionTransition::establish(authentication));
                    response.headers_mut().append(
                        header::SET_COOKIE,
                        HeaderValue::from_static("local_session=application-value"),
                    );
                    response
                }
            }),
        );
    let running = Application::new(routes)
        .bind(loopback())
        .security(browser_security(Arc::clone(&state))?)?
        .start()
        .await?;
    let address = running.address();

    let login = http_request(
        address,
        "POST",
        "/login",
        &[("Origin", "http://localhost")],
        "",
    )
    .await;
    assert!(login.starts_with("HTTP/1.1 200"), "{login}");
    let session = response_cookie(&login, "local_session").expect("session cookie");
    let csrf = response_cookie(&login, "XSRF-TOKEN").expect("CSRF cookie");
    let lower_login = login.to_ascii_lowercase();
    let session_line = lower_login
        .lines()
        .find(|line| line.contains("local_session="))
        .expect("session Set-Cookie");
    let csrf_line = lower_login
        .lines()
        .find(|line| line.contains("xsrf-token="))
        .expect("CSRF Set-Cookie");
    assert!(session_line.contains("httponly"), "{session_line}");
    assert!(!csrf_line.contains("httponly"), "{csrf_line}");

    let cookie = format!("local_session={session}; XSRF-TOKEN={csrf}");
    let who = request(address, "/who", &[("Cookie", &cookie)]).await;
    assert!(who.starts_with("HTTP/1.1 200"), "{who}");
    assert!(who.ends_with("browser-user"), "{who}");
    let csrf_recovery_cookie = format!("local_session={session}");
    let csrf_recovery = request(address, "/csrf", &[("Cookie", &csrf_recovery_cookie)]).await;
    assert!(csrf_recovery.starts_with("HTTP/1.1 200"), "{csrf_recovery}");
    assert_eq!(
        response_cookie(&csrf_recovery, "XSRF-TOKEN"),
        Some(csrf.clone())
    );
    assert_eq!(response_cookie(&csrf_recovery, "local_session"), None);

    let missing_csrf = http_request(
        address,
        "POST",
        "/mutate",
        &[("Origin", "http://localhost"), ("Cookie", &cookie)],
        "",
    )
    .await;
    assert!(missing_csrf.starts_with("HTTP/1.1 403"), "{missing_csrf}");
    let foreign_origin = http_request(
        address,
        "POST",
        "/mutate",
        &[
            ("Origin", "https://attacker.example"),
            ("Cookie", &cookie),
            ("X-XSRF-TOKEN", &csrf),
        ],
        "",
    )
    .await;
    assert!(
        foreign_origin.starts_with("HTTP/1.1 403"),
        "{foreign_origin}"
    );
    let mutation = http_request(
        address,
        "POST",
        "/mutate",
        &[
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
            ("X-XSRF-TOKEN", &csrf),
        ],
        "",
    )
    .await;
    assert!(mutation.starts_with("HTTP/1.1 200"), "{mutation}");
    assert!(mutation.ends_with("mutated"), "{mutation}");

    let ambiguous = request(
        address,
        "/who",
        &[
            ("Cookie", &cookie),
            ("Authorization", "Bearer reader-token"),
        ],
    )
    .await;
    assert!(ambiguous.starts_with("HTTP/1.1 400"), "{ambiguous}");

    let refresh = http_request(
        address,
        "POST",
        "/refresh",
        &[
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
            ("X-XSRF-TOKEN", &csrf),
        ],
        "",
    )
    .await;
    assert!(refresh.starts_with("HTTP/1.1 200"), "{refresh}");
    let refreshed_session = response_cookie(&refresh, "local_session").expect("rotated session");
    let refreshed_csrf = response_cookie(&refresh, "XSRF-TOKEN").expect("rotated CSRF");
    assert_ne!(session, refreshed_session);
    assert_ne!(csrf, refreshed_csrf);

    let replay = request(address, "/who", &[("Cookie", &cookie)]).await;
    assert!(replay.starts_with("HTTP/1.1 401"), "{replay}");
    assert_eq!(
        response_cookie(&replay, "local_session"),
        Some(String::new())
    );
    let refreshed_cookie =
        format!("local_session={refreshed_session}; XSRF-TOKEN={refreshed_csrf}");
    let stale_token = http_request(
        address,
        "POST",
        "/mutate",
        &[
            ("Origin", "http://localhost"),
            ("Cookie", &refreshed_cookie),
            ("X-XSRF-TOKEN", &csrf),
        ],
        "",
    )
    .await;
    assert!(stale_token.starts_with("HTTP/1.1 403"), "{stale_token}");

    let saved_before_conflict = state.session_count();
    let conflict = http_request(
        address,
        "POST",
        "/conflict-login",
        &[("Origin", "http://localhost")],
        "",
    )
    .await;
    assert!(conflict.starts_with("HTTP/1.1 503"), "{conflict}");
    assert!(!has_set_cookie(&conflict), "{conflict}");
    assert_eq!(state.session_count(), saved_before_conflict + 1);

    let logout = http_request(
        address,
        "POST",
        "/logout",
        &[
            ("Origin", "http://localhost"),
            ("Cookie", &refreshed_cookie),
            ("X-XSRF-TOKEN", &refreshed_csrf),
        ],
        "",
    )
    .await;
    assert!(logout.starts_with("HTTP/1.1 200"), "{logout}");
    assert_eq!(
        response_cookie(&logout, "local_session"),
        Some(String::new())
    );
    assert_eq!(response_cookie(&logout, "XSRF-TOKEN"), Some(String::new()));
    let logged_out_replay = request(address, "/who", &[("Cookie", &refreshed_cookie)]).await;
    assert!(
        logged_out_replay.starts_with("HTTP/1.1 401"),
        "{logged_out_replay}"
    );

    running.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unconfirmed_session_save_emits_no_login_cookie() -> TestResult {
    let state = Arc::new(BrowserState::with_unconfirmed_saves());
    let login_authentication = authentication("uncertain-user", &[])?;
    let routes = Router::new().route(
        "/login",
        post(move || {
            let authentication = login_authentication.clone();
            async move { Extension(SessionTransition::establish(authentication)) }
        }),
    );
    let running = Application::new(routes)
        .bind(loopback())
        .security(browser_security(Arc::clone(&state))?)?
        .start()
        .await?;
    let response = http_request(
        running.address(),
        "POST",
        "/login",
        &[("Origin", "http://localhost")],
        "",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(!has_set_cookie(&response), "{response}");
    assert_eq!(state.session_count(), 1);
    running.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn refresh_rejects_a_strategy_that_reuses_the_presented_identifier() -> TestResult {
    let state = Arc::new(BrowserState::default());
    let login_authentication = authentication("fixed-user", &[])?;
    let routes = Router::new()
        .route(
            "/login",
            post(move || {
                let authentication = login_authentication.clone();
                async move { Extension(SessionTransition::establish(authentication)) }
            }),
        )
        .route(
            "/refresh",
            post(|| async { Extension(SessionTransition::refresh()) }),
        );
    let security =
        browser_security_with_strategy(Arc::clone(&state), Arc::new(NonRotatingStrategy))?;
    let running = Application::new(routes)
        .bind(loopback())
        .security(security)?
        .start()
        .await?;
    let login = http_request(
        running.address(),
        "POST",
        "/login",
        &[("Origin", "http://localhost")],
        "",
    )
    .await;
    let session = response_cookie(&login, "local_session").expect("session");
    let csrf = response_cookie(&login, "XSRF-TOKEN").expect("CSRF");
    let cookie = format!("local_session={session}; XSRF-TOKEN={csrf}");
    let refresh = http_request(
        running.address(),
        "POST",
        "/refresh",
        &[
            ("Origin", "http://localhost"),
            ("Cookie", &cookie),
            ("X-XSRF-TOKEN", &csrf),
        ],
        "",
    )
    .await;
    assert!(refresh.starts_with("HTTP/1.1 503"), "{refresh}");
    assert!(!has_set_cookie(&refresh), "{refresh}");
    assert_eq!(state.session_count(), 1);
    running.shutdown().await?;
    Ok(())
}

struct DropSignal(Arc<AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct PendingContextRepository {
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl SecurityContextRepository for PendingContextRepository {
    fn load<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        _identifier: &'a SessionIdentifier,
    ) -> SecurityContextLoadFuture<'a> {
        let started = Arc::clone(&self.started);
        let dropped = Arc::clone(&self.dropped);
        Box::pin(async move {
            let _signal = DropSignal(dropped);
            started.store(true, Ordering::SeqCst);
            future::pending::<Result<SecurityContextLoad, SessionOperationError>>().await
        })
    }

    fn save<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        _previous: Option<&'a SessionIdentifier>,
        _identifier: &'a SessionIdentifier,
        _context: &'a SecurityContext,
    ) -> SessionWriteFuture<'a> {
        Box::pin(async { Err(SessionOperationError::Internal) })
    }

    fn invalidate<'a>(
        &'a self,
        _request: &'a RequestMetadata,
        _identifier: &'a SessionIdentifier,
    ) -> SessionWriteFuture<'a> {
        Box::pin(async { Err(SessionOperationError::Internal) })
    }
}

#[tokio::test]
async fn outer_deadline_cancels_context_loading_without_invoking_the_handler() -> TestResult {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let invoked = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&invoked);
    let origin = BrowserOrigin::loopback_http("http://localhost")?;
    let transport = BrowserCookie::new(
        &origin,
        CookieName::new("local_session")?,
        SameSite::Lax,
        CookieVisibility::HttpOnly,
    )?;
    let cookie = SessionCookie::new(
        transport,
        CookieLifetime::Session,
        CookieHeaderPolicy::TargetOnly,
    )?;
    let strategy = Arc::new(BrowserState::default());
    let mut stateful = StatefulSecurity::builder();
    stateful.context_repository(Arc::new(PendingContextRepository {
        started: Arc::clone(&started),
        dropped: Arc::clone(&dropped),
    }));
    stateful.session_authentication_strategy(strategy);
    stateful.session_cookie(cookie);
    // This test-only GET-only chain accepts no unsafe route.
    stateful.csrf_disabled();
    let mut chain = SecurityChain::builder(
        SecurityComponentId::new("pending-context")?,
        1,
        Arc::new(butter_security_web::AnyRequest),
    );
    chain.authorization_manager(Arc::new(PermitAll));
    chain.neutral_handlers();
    chain.stateful_security(stateful.build()?);
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
        &[("Cookie", "local_session=pending-session")],
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
