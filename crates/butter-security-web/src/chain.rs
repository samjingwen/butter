use crate::{
    AccessDeniedHandler, AuthenticationEntryPoint, CredentialExtraction,
    CredentialExtractionFailure, CredentialExtractor, CredentialSource, CsrfProtection,
    CsrfTokenLoad, ExploitProtectionFailure, MatcherDescriptor, NeutralAccessDeniedHandler,
    NeutralAuthenticationEntryPoint, RequestMatcher, RequestMetadata, SecurityContextLoad,
    SessionIdentifier, SessionTransition, StatefulSecurity, WebAuthenticationFailure,
    csrf::tokens_equal,
    matcher::descriptor_covers,
    response::empty_response,
    session::{CsrfDecision, SessionTransitionKind},
};
use butter_security::{
    AuthenticationManager, AuthorizationFailure, AuthorizationManager, SecurityContext, authorize,
};
use butter_web::{
    Router,
    native::{
        extract::{Request, State},
        http::{HeaderMap, StatusCode},
        middleware::{self, Next},
        response::Response,
    },
};
use std::{collections::HashSet, error::Error, fmt, sync::Arc};

const MAX_IDENTIFIER_BYTES: usize = 64;
const MAX_CHAINS: usize = 64;
const MAX_EXTRACTORS: usize = 64;

/// Framework-owned semantic stage anchors in execution order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PipelineStage {
    /// Validate normalized request structure and ambiguity.
    RequestIntegrity,
    /// Establish request-local anonymous state.
    ContextLoad,
    /// Reserved anchor for explicitly configured exploit protection.
    ExploitProtection,
    /// Extract bounded credentials and reject conflicts.
    CredentialExtraction,
    /// Authenticate one recognized credential request.
    Authentication,
    /// Reserved anchor for a later session transition policy.
    SessionTransition,
    /// Enforce fail-closed request authorization.
    Authorization,
    /// Invoke the guarded application route.
    ApplicationInvocation,
    /// Reserved anchor for later context persistence.
    ContextPersistence,
    /// Complete or translate the response.
    ResponseCompletion,
}

/// Canonical pipeline ordering owned by the framework.
pub const PIPELINE_STAGES: [PipelineStage; 10] = [
    PipelineStage::RequestIntegrity,
    PipelineStage::ContextLoad,
    PipelineStage::ExploitProtection,
    PipelineStage::CredentialExtraction,
    PipelineStage::Authentication,
    PipelineStage::SessionTransition,
    PipelineStage::Authorization,
    PipelineStage::ApplicationInvocation,
    PipelineStage::ContextPersistence,
    PipelineStage::ResponseCompletion,
];

/// Validated, non-secret identifier for a chain or named stage component.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecurityComponentId(Arc<str>);

impl SecurityComponentId {
    /// Validates 1-64 ASCII alphanumeric, dot, underscore or hyphen bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityBuildError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_IDENTIFIER_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if !valid {
            return Err(SecurityBuildError::InvalidIdentifier);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the safe identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Invalid chain or proxy construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityBuildError {
    /// A chain or stage identifier was invalid.
    InvalidIdentifier,
    /// A chain omitted its authorization manager.
    MissingAuthorizationManager,
    /// A chain omitted its authentication entry point.
    MissingAuthenticationEntryPoint,
    /// A chain omitted its access-denied handler.
    MissingAccessDeniedHandler,
    /// Credential extractors were configured without an authentication manager.
    MissingAuthenticationManager,
    /// An authentication manager had no credential extractor.
    MissingCredentialExtractor,
    /// A named stage component was repeated in one chain.
    DuplicateStage,
    /// A chain exceeded the credential extractor bound.
    ExtractorLimit,
    /// The proxy exceeded the chain bound.
    ChainLimit,
    /// Chain identifiers must be unique.
    DuplicateChain,
    /// Chain priorities must be unique.
    DuplicatePriority,
    /// An earlier provably broad matcher made a later chain unreachable.
    ShadowedChain,
    /// The proxy requires an explicit unmatched-request policy.
    MissingUnmatchedPolicy,
}

impl fmt::Display for SecurityBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "invalid web security component identifier",
            Self::MissingAuthorizationManager => "security chain requires authorization policy",
            Self::MissingAuthenticationEntryPoint => {
                "security chain requires an authentication entry point"
            }
            Self::MissingAccessDeniedHandler => "security chain requires an access-denied handler",
            Self::MissingAuthenticationManager => {
                "credential extractors require an authentication manager"
            }
            Self::MissingCredentialExtractor => {
                "authentication manager requires a credential extractor"
            }
            Self::DuplicateStage => "duplicate named security stage component",
            Self::ExtractorLimit => "security chain credential extractor limit exceeded",
            Self::ChainLimit => "web security chain limit exceeded",
            Self::DuplicateChain => "duplicate web security chain identifier",
            Self::DuplicatePriority => "duplicate web security chain priority",
            Self::ShadowedChain => "an earlier security chain shadows a later chain",
            Self::MissingUnmatchedPolicy => "web security requires an unmatched-request policy",
        })
    }
}

impl Error for SecurityBuildError {}

struct RegisteredExtractor {
    id: SecurityComponentId,
    extractor: Arc<dyn CredentialExtractor>,
}

/// One validated first-match security chain.
pub struct SecurityChain {
    id: SecurityComponentId,
    priority: u16,
    matcher: Arc<dyn RequestMatcher>,
    descriptor: MatcherDescriptor,
    extractors: Vec<RegisteredExtractor>,
    authentication_manager: Option<Arc<dyn AuthenticationManager>>,
    authorization_manager: Arc<dyn AuthorizationManager<RequestMetadata>>,
    entry_point: Arc<dyn AuthenticationEntryPoint>,
    denied_handler: Arc<dyn AccessDeniedHandler>,
    stateful: Option<Arc<StatefulSecurity>>,
}

impl SecurityChain {
    /// Starts a chain builder. Lower priorities are evaluated first.
    #[must_use]
    pub fn builder(
        id: SecurityComponentId,
        priority: u16,
        matcher: Arc<dyn RequestMatcher>,
    ) -> SecurityChainBuilder {
        SecurityChainBuilder {
            id,
            priority,
            matcher,
            extractors: Vec::new(),
            authentication_manager: None,
            authorization_manager: None,
            entry_point: None,
            denied_handler: None,
            stateful: None,
        }
    }

    /// Returns the safe chain identifier.
    #[must_use]
    pub fn id(&self) -> &SecurityComponentId {
        &self.id
    }

    /// Returns the first-match priority. Lower values run first.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns a safe matcher description.
    #[must_use]
    pub const fn matcher(&self) -> &MatcherDescriptor {
        &self.descriptor
    }

    /// Returns the immutable canonical stage ordering.
    pub fn stages(&self) -> impl ExactSizeIterator<Item = PipelineStage> {
        PIPELINE_STAGES.into_iter()
    }

    /// Returns stateful browser security when this is not a stateless chain.
    #[must_use]
    pub fn stateful_security(&self) -> Option<&StatefulSecurity> {
        self.stateful.as_deref()
    }
}

/// Explicit builder for one security chain.
pub struct SecurityChainBuilder {
    id: SecurityComponentId,
    priority: u16,
    matcher: Arc<dyn RequestMatcher>,
    extractors: Vec<RegisteredExtractor>,
    authentication_manager: Option<Arc<dyn AuthenticationManager>>,
    authorization_manager: Option<Arc<dyn AuthorizationManager<RequestMetadata>>>,
    entry_point: Option<Arc<dyn AuthenticationEntryPoint>>,
    denied_handler: Option<Arc<dyn AccessDeniedHandler>>,
    stateful: Option<Arc<StatefulSecurity>>,
}

impl SecurityChainBuilder {
    /// Adds one named extractor at the credential-extraction stage.
    pub fn credential_extractor(
        &mut self,
        id: SecurityComponentId,
        extractor: Arc<dyn CredentialExtractor>,
    ) -> Result<&mut Self, SecurityBuildError> {
        if self.extractors.len() == MAX_EXTRACTORS {
            return Err(SecurityBuildError::ExtractorLimit);
        }
        if self.extractors.iter().any(|registered| registered.id == id) {
            return Err(SecurityBuildError::DuplicateStage);
        }
        self.extractors.push(RegisteredExtractor { id, extractor });
        Ok(self)
    }

    /// Installs credential verification for extracted requests.
    pub fn authentication_manager(&mut self, manager: Arc<dyn AuthenticationManager>) -> &mut Self {
        self.authentication_manager = Some(manager);
        self
    }

    /// Installs fail-closed request authorization.
    pub fn authorization_manager(
        &mut self,
        manager: Arc<dyn AuthorizationManager<RequestMetadata>>,
    ) -> &mut Self {
        self.authorization_manager = Some(manager);
        self
    }

    /// Installs authentication failure translation.
    pub fn authentication_entry_point(
        &mut self,
        entry_point: Arc<dyn AuthenticationEntryPoint>,
    ) -> &mut Self {
        self.entry_point = Some(entry_point);
        self
    }

    /// Installs authorization failure translation.
    pub fn access_denied_handler(&mut self, handler: Arc<dyn AccessDeniedHandler>) -> &mut Self {
        self.denied_handler = Some(handler);
        self
    }

    /// Installs empty, cache-resistant standard HTTP failure handlers.
    pub fn neutral_handlers(&mut self) -> &mut Self {
        self.authentication_entry_point(Arc::new(NeutralAuthenticationEntryPoint::new()));
        self.access_denied_handler(Arc::new(NeutralAccessDeniedHandler));
        self
    }

    /// Enables explicit stateful browser security for this chain.
    pub fn stateful_security(&mut self, stateful: StatefulSecurity) -> &mut Self {
        self.stateful = Some(Arc::new(stateful));
        self
    }

    /// Validates and completes the chain.
    pub fn build(self) -> Result<SecurityChain, SecurityBuildError> {
        match (
            self.extractors.is_empty(),
            self.authentication_manager.is_some(),
        ) {
            (false, false) => return Err(SecurityBuildError::MissingAuthenticationManager),
            (true, true) => return Err(SecurityBuildError::MissingCredentialExtractor),
            _ => {}
        }
        let descriptor = self.matcher.descriptor();
        Ok(SecurityChain {
            id: self.id,
            priority: self.priority,
            matcher: self.matcher,
            descriptor,
            extractors: self.extractors,
            authentication_manager: self.authentication_manager,
            authorization_manager: self
                .authorization_manager
                .ok_or(SecurityBuildError::MissingAuthorizationManager)?,
            entry_point: self
                .entry_point
                .ok_or(SecurityBuildError::MissingAuthenticationEntryPoint)?,
            denied_handler: self
                .denied_handler
                .ok_or(SecurityBuildError::MissingAccessDeniedHandler)?,
            stateful: self.stateful,
        })
    }
}

/// Explicit behavior when no configured chain matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnmatchedPolicy {
    /// Reject without invoking the application. The neutral response is `404`.
    Deny,
    /// Invoke the application with an anonymous request context.
    Permit,
}

/// Builder for first-match web security.
#[derive(Default)]
pub struct SecurityWebBuilder {
    chains: Vec<SecurityChain>,
    unmatched: Option<UnmatchedPolicy>,
}

impl SecurityWebBuilder {
    /// Adds one validated chain. Final ordering uses ascending priority.
    pub fn chain(&mut self, chain: SecurityChain) -> Result<&mut Self, SecurityBuildError> {
        if self.chains.len() == MAX_CHAINS {
            return Err(SecurityBuildError::ChainLimit);
        }
        self.chains.push(chain);
        Ok(self)
    }

    /// Selects explicit behavior for requests unmatched by every chain.
    pub fn unmatched_policy(&mut self, policy: UnmatchedPolicy) -> &mut Self {
        self.unmatched = Some(policy);
        self
    }

    /// Validates priorities, identities, conservative shadowing and fallback.
    pub fn build(mut self) -> Result<SecurityWeb, SecurityBuildError> {
        let unmatched = self
            .unmatched
            .ok_or(SecurityBuildError::MissingUnmatchedPolicy)?;
        self.chains.sort_by_key(SecurityChain::priority);
        let mut ids = HashSet::new();
        let mut priorities = HashSet::new();
        for chain in &self.chains {
            if !ids.insert(chain.id.clone()) {
                return Err(SecurityBuildError::DuplicateChain);
            }
            if !priorities.insert(chain.priority) {
                return Err(SecurityBuildError::DuplicatePriority);
            }
        }
        for (index, earlier) in self.chains.iter().enumerate() {
            for later in &self.chains[index + 1..] {
                if descriptor_covers(&earlier.descriptor, &later.descriptor) {
                    return Err(SecurityBuildError::ShadowedChain);
                }
            }
        }
        Ok(SecurityWeb {
            inner: Arc::new(SecurityWebInner {
                chains: self.chains,
                unmatched,
            }),
        })
    }
}

struct SecurityWebInner {
    chains: Vec<SecurityChain>,
    unmatched: UnmatchedPolicy,
}

/// Immutable, validated first-match security boundary.
#[derive(Clone)]
pub struct SecurityWeb {
    inner: Arc<SecurityWebInner>,
}

impl SecurityWeb {
    /// Starts explicit security-boundary construction.
    #[must_use]
    pub fn builder() -> SecurityWebBuilder {
        SecurityWebBuilder::default()
    }

    /// Applies security to guarded application routes before HTTP assembly.
    ///
    /// Applications using `butter-boot` should prefer
    /// `Application::security`, which performs this operation only after route
    /// construction. This lower-level method applies only to routes already in
    /// `routes`; Axum layers do not cover routes appended afterward.
    ///
    /// Route inventory is preserved. Butter's outer boundary still owns
    /// admission, response deadlines, observation and graceful shutdown, while
    /// separately attached Actuator reads remain outside this application layer.
    pub fn protect(&self, routes: Router) -> Router {
        routes.layer(middleware::from_fn_with_state(
            self.clone(),
            security_middleware,
        ))
    }

    /// Returns chains in actual first-match order.
    pub fn chains(&self) -> impl ExactSizeIterator<Item = &SecurityChain> {
        self.inner.chains.iter()
    }

    /// Returns the explicit unmatched-request policy.
    #[must_use]
    pub fn unmatched_policy(&self) -> UnmatchedPolicy {
        self.inner.unmatched
    }
}

async fn security_middleware(
    State(security): State<SecurityWeb>,
    mut request: Request,
    next: Next,
) -> Response {
    let metadata =
        match RequestMetadata::from_parts(request.method(), request.uri(), request.headers()) {
            Ok(metadata) => metadata,
            Err(_) => return empty_response(StatusCode::BAD_REQUEST),
        };
    let Some(chain) = security
        .inner
        .chains
        .iter()
        .find(|chain| chain.matcher.matches(&metadata))
    else {
        return match security.inner.unmatched {
            UnmatchedPolicy::Deny => empty_response(StatusCode::NOT_FOUND),
            UnmatchedPolicy::Permit => {
                request
                    .extensions_mut()
                    .insert(SecurityContext::anonymous());
                let mut response = next.run(request).await;
                if response
                    .extensions_mut()
                    .remove::<SessionTransition>()
                    .is_some()
                {
                    operational_failure_response()
                } else {
                    response
                }
            }
        };
    };

    let loaded = match load_context(chain, &metadata, request.headers()).await {
        Ok(loaded) => loaded,
        Err(ContextLoadStepFailure::MalformedCookie) => {
            return empty_response(StatusCode::BAD_REQUEST);
        }
        Err(ContextLoadStepFailure::Operational) => return operational_failure_response(),
    };
    if let Some(stateful) = chain.stateful.as_deref()
        && let CsrfDecision::Enabled(protection) = &stateful.csrf
        && let Err(failure) = enforce_exploit_protection(
            protection,
            &metadata,
            request.headers(),
            loaded.identifier.as_ref(),
        )
        .await
    {
        let response = match failure {
            ExploitProtectionStepFailure::Denied(failure) => {
                protection.denied_handler.denied(&metadata, failure).await
            }
            ExploitProtectionStepFailure::Operational => operational_failure_response(),
        };
        return finish_invalid_session(stateful, loaded.invalid, response);
    }

    let source = CredentialSource::new(request.method(), request.uri(), request.headers());
    let authentication = match authenticate(
        chain,
        source,
        loaded.context.clone(),
        loaded.identifier.is_some(),
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(AuthenticationStepFailure::Extraction(failure)) => {
            let response = chain
                .entry_point
                .commence(&metadata, WebAuthenticationFailure::Extraction(failure))
                .await;
            return finish_invalid_session_option(chain, loaded.invalid, response);
        }
        Err(AuthenticationStepFailure::Authentication(failure)) => {
            let response = chain
                .entry_point
                .commence(&metadata, WebAuthenticationFailure::Authentication(failure))
                .await;
            return finish_invalid_session_option(chain, loaded.invalid, response);
        }
    };

    let prepared_identifier = if authentication.fresh {
        if let Some(stateful) = chain.stateful.as_deref() {
            match stateful
                .strategy
                .rotate(&metadata, None, &authentication.context)
                .await
            {
                Ok(identifier) => Some(identifier),
                Err(_) => return operational_failure_response(),
            }
        } else {
            None
        }
    } else {
        None
    };

    match authorize(
        chain.authorization_manager.as_ref(),
        &authentication.context,
        &metadata,
    )
    .await
    {
        Ok(()) => {
            request
                .extensions_mut()
                .insert(authentication.context.clone());
            let mut response = next.run(request).await;
            let transition = response.extensions_mut().remove::<SessionTransition>();
            if let Some(stateful) = chain.stateful.as_deref() {
                complete_stateful_response(
                    stateful,
                    &metadata,
                    loaded,
                    authentication,
                    prepared_identifier,
                    transition,
                    response,
                )
                .await
            } else if transition.is_some() {
                operational_failure_response()
            } else {
                response
            }
        }
        Err(failure @ (AuthorizationFailure::Denied | AuthorizationFailure::NoGrant))
            if !authentication.context.is_authenticated() =>
        {
            let _ = failure;
            let response = chain
                .entry_point
                .commence(&metadata, WebAuthenticationFailure::MissingCredentials)
                .await;
            finish_invalid_session_option(chain, loaded.invalid, response)
        }
        Err(failure) => {
            let response = chain.denied_handler.denied(&metadata, failure).await;
            finish_invalid_session_option(chain, loaded.invalid, response)
        }
    }
}

async fn authenticate(
    chain: &SecurityChain,
    source: CredentialSource<'_>,
    loaded_context: SecurityContext,
    browser_credential_present: bool,
) -> Result<AuthenticationStep, AuthenticationStepFailure> {
    let mut extracted = None;
    for registered in &chain.extractors {
        match registered.extractor.extract(source) {
            Ok(CredentialExtraction::Missing) => {}
            Ok(CredentialExtraction::Present(authentication_request)) if extracted.is_none() => {
                extracted = Some(authentication_request);
            }
            Ok(CredentialExtraction::Present(_)) => {
                return Err(AuthenticationStepFailure::Extraction(
                    CredentialExtractionFailure::Ambiguous,
                ));
            }
            Err(failure) => {
                return Err(AuthenticationStepFailure::Extraction(failure));
            }
        }
    }
    let Some(authentication_request) = extracted else {
        return Ok(AuthenticationStep {
            context: loaded_context,
            fresh: false,
        });
    };
    if browser_credential_present {
        return Err(AuthenticationStepFailure::Extraction(
            CredentialExtractionFailure::Ambiguous,
        ));
    }
    let Some(manager) = chain.authentication_manager.as_ref() else {
        return Err(AuthenticationStepFailure::Authentication(
            butter_security::AuthenticationFailure::Operational(
                butter_security::AuthenticationOperationalError::Internal,
            ),
        ));
    };
    match manager.authenticate(authentication_request.as_ref()).await {
        Ok(authentication) => Ok(AuthenticationStep {
            context: authentication.into_context(),
            fresh: true,
        }),
        Err(failure) => Err(AuthenticationStepFailure::Authentication(failure)),
    }
}

struct AuthenticationStep {
    context: SecurityContext,
    fresh: bool,
}

struct LoadedSession {
    identifier: Option<SessionIdentifier>,
    context: SecurityContext,
    invalid: bool,
}

async fn load_context(
    chain: &SecurityChain,
    metadata: &RequestMetadata,
    headers: &HeaderMap,
) -> Result<LoadedSession, ContextLoadStepFailure> {
    let Some(stateful) = chain.stateful.as_deref() else {
        return Ok(LoadedSession {
            identifier: None,
            context: SecurityContext::anonymous(),
            invalid: false,
        });
    };
    let identifier = stateful
        .cookie
        .read(headers)
        .map_err(|_| ContextLoadStepFailure::MalformedCookie)?;
    let Some(identifier) = identifier else {
        return Ok(LoadedSession {
            identifier: None,
            context: SecurityContext::anonymous(),
            invalid: false,
        });
    };
    let (context, invalid) = match stateful.repository.load(metadata, &identifier).await {
        Ok(SecurityContextLoad::Active(context)) if context.is_authenticated() => (context, false),
        Ok(SecurityContextLoad::Missing | SecurityContextLoad::Invalid) => {
            (SecurityContext::anonymous(), true)
        }
        Ok(SecurityContextLoad::Active(_)) | Err(_) => {
            return Err(ContextLoadStepFailure::Operational);
        }
    };
    Ok(LoadedSession {
        identifier: Some(identifier),
        context,
        invalid,
    })
}

async fn enforce_exploit_protection(
    protection: &CsrfProtection,
    metadata: &RequestMetadata,
    headers: &HeaderMap,
    identifier: Option<&SessionIdentifier>,
) -> Result<(), ExploitProtectionStepFailure> {
    if !protection.unsafe_matcher.matches(metadata) {
        return Ok(());
    }
    protection.origin_policy.check(headers).map_err(|failure| {
        ExploitProtectionStepFailure::Denied(ExploitProtectionFailure::Origin(failure))
    })?;
    let Some(identifier) = identifier else {
        return Ok(());
    };
    let presented = protection
        .request_handler
        .resolve(headers)
        .map_err(|_| ExploitProtectionStepFailure::Denied(ExploitProtectionFailure::Csrf))?;
    let expected = protection
        .repository
        .load(metadata, identifier)
        .await
        .map_err(|_| ExploitProtectionStepFailure::Operational)?;
    match (expected, presented) {
        (CsrfTokenLoad::Found(expected), Some(presented))
            if tokens_equal(&expected, &presented) =>
        {
            Ok(())
        }
        _ => Err(ExploitProtectionStepFailure::Denied(
            ExploitProtectionFailure::Csrf,
        )),
    }
}

async fn complete_stateful_response(
    stateful: &StatefulSecurity,
    metadata: &RequestMetadata,
    loaded: LoadedSession,
    authentication: AuthenticationStep,
    prepared_identifier: Option<SessionIdentifier>,
    transition: Option<SessionTransition>,
    response: Response,
) -> Response {
    if authentication.fresh && transition.is_some() {
        return operational_failure_response();
    }
    if transition.is_some()
        && !(response.status().is_success() || response.status().is_redirection())
    {
        return operational_failure_response();
    }
    if !(response.status().is_success() || response.status().is_redirection()) {
        return finish_invalid_session(stateful, loaded.invalid, response);
    }

    let transition = transition.map(|transition| transition.kind).or_else(|| {
        authentication
            .fresh
            .then_some(SessionTransitionKind::Establish(
                authentication.context.clone(),
            ))
    });
    match transition {
        Some(SessionTransitionKind::Establish(context)) => {
            establish_session(
                stateful,
                metadata,
                loaded.identifier.as_ref(),
                &context,
                prepared_identifier,
                response,
            )
            .await
        }
        Some(SessionTransitionKind::Refresh) => {
            if loaded.invalid
                || loaded.identifier.is_none()
                || !authentication.context.is_authenticated()
            {
                return operational_failure_response();
            }
            establish_session(
                stateful,
                metadata,
                loaded.identifier.as_ref(),
                &authentication.context,
                None,
                response,
            )
            .await
        }
        Some(SessionTransitionKind::ExposeCsrf) => {
            let Some(identifier) = loaded.identifier.as_ref() else {
                return operational_failure_response();
            };
            if loaded.invalid || !authentication.context.is_authenticated() {
                return operational_failure_response();
            }
            expose_csrf_token(stateful, metadata, identifier, response).await
        }
        Some(SessionTransitionKind::Logout) => {
            logout_session(stateful, metadata, loaded.identifier.as_ref(), response).await
        }
        None => finish_invalid_session(stateful, loaded.invalid, response),
    }
}

async fn expose_csrf_token(
    stateful: &StatefulSecurity,
    metadata: &RequestMetadata,
    identifier: &SessionIdentifier,
    mut response: Response,
) -> Response {
    let CsrfDecision::Enabled(protection) = &stateful.csrf else {
        return operational_failure_response();
    };
    let token = match protection.repository.load(metadata, identifier).await {
        Ok(CsrfTokenLoad::Found(token)) => token,
        Ok(CsrfTokenLoad::Missing) | Err(_) => return operational_failure_response(),
    };
    if protection
        .request_handler
        .expose(response.headers_mut(), &token)
        .is_err()
    {
        return operational_failure_response();
    }
    response
}

async fn establish_session(
    stateful: &StatefulSecurity,
    metadata: &RequestMetadata,
    previous: Option<&SessionIdentifier>,
    context: &SecurityContext,
    prepared_identifier: Option<SessionIdentifier>,
    mut response: Response,
) -> Response {
    if !context.is_authenticated() {
        return operational_failure_response();
    }
    let identifier = match prepared_identifier {
        Some(identifier) => identifier,
        None => match stateful.strategy.rotate(metadata, previous, context).await {
            Ok(identifier) => identifier,
            Err(_) => return operational_failure_response(),
        },
    };
    if previous.is_some_and(|previous| {
        crate::session::secret_values_equal(previous.expose_secret(), identifier.expose_secret())
    }) {
        return operational_failure_response();
    }
    if stateful
        .repository
        .save(metadata, previous, &identifier, context)
        .await
        .is_err()
    {
        return operational_failure_response();
    }
    let csrf_token = match &stateful.csrf {
        CsrfDecision::Enabled(protection) => {
            let token = match previous {
                Some(previous) => {
                    protection
                        .repository
                        .rotate(metadata, previous, &identifier)
                        .await
                }
                None => protection.repository.create(metadata, &identifier).await,
            };
            match token {
                Ok(token) => Some((protection, token)),
                Err(_) => return operational_failure_response(),
            }
        }
        CsrfDecision::Disabled => None,
    };
    if stateful
        .cookie
        .append(response.headers_mut(), &identifier)
        .is_err()
    {
        return operational_failure_response();
    }
    if let Some((protection, token)) = csrf_token
        && protection
            .request_handler
            .expose(response.headers_mut(), &token)
            .is_err()
    {
        return operational_failure_response();
    }
    response
}

async fn logout_session(
    stateful: &StatefulSecurity,
    metadata: &RequestMetadata,
    identifier: Option<&SessionIdentifier>,
    mut response: Response,
) -> Response {
    if let Some(identifier) = identifier {
        if stateful
            .repository
            .invalidate(metadata, identifier)
            .await
            .is_err()
        {
            return operational_failure_response();
        }
        if let CsrfDecision::Enabled(protection) = &stateful.csrf
            && protection
                .repository
                .invalidate(metadata, identifier)
                .await
                .is_err()
        {
            return operational_failure_response();
        }
    }
    if remove_browser_cookies(stateful, response.headers_mut()).is_err() {
        return operational_failure_response();
    }
    response
}

fn finish_invalid_session(
    stateful: &StatefulSecurity,
    invalid: bool,
    mut response: Response,
) -> Response {
    if invalid && remove_browser_cookies(stateful, response.headers_mut()).is_err() {
        operational_failure_response()
    } else {
        response
    }
}

fn finish_invalid_session_option(
    chain: &SecurityChain,
    invalid: bool,
    response: Response,
) -> Response {
    match chain.stateful.as_deref() {
        Some(stateful) => finish_invalid_session(stateful, invalid, response),
        None => response,
    }
}

fn remove_browser_cookies(stateful: &StatefulSecurity, headers: &mut HeaderMap) -> Result<(), ()> {
    stateful.cookie.append_removal(headers).map_err(|_| ())?;
    if let CsrfDecision::Enabled(protection) = &stateful.csrf {
        protection.request_handler.remove(headers).map_err(|_| ())?;
    }
    Ok(())
}

fn operational_failure_response() -> Response {
    empty_response(StatusCode::SERVICE_UNAVAILABLE)
}

enum ContextLoadStepFailure {
    MalformedCookie,
    Operational,
}

enum ExploitProtectionStepFailure {
    Denied(ExploitProtectionFailure),
    Operational,
}

enum AuthenticationStepFailure {
    Extraction(CredentialExtractionFailure),
    Authentication(butter_security::AuthenticationFailure),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnyRequest, ExactPathMatcher, PathPrefixMatcher};
    use butter_security::PermitAll;

    fn chain(
        id: &str,
        priority: u16,
        matcher: Arc<dyn RequestMatcher>,
    ) -> Result<SecurityChain, Box<dyn Error>> {
        let mut builder = SecurityChain::builder(SecurityComponentId::new(id)?, priority, matcher);
        builder.authorization_manager(Arc::new(PermitAll));
        builder.neutral_handlers();
        Ok(builder.build()?)
    }

    #[test]
    fn builder_rejects_missing_policy_duplicates_and_broad_shadowing() -> Result<(), Box<dyn Error>>
    {
        let mut missing = SecurityWeb::builder();
        missing.chain(chain("one", 1, Arc::new(AnyRequest))?)?;
        assert!(matches!(
            missing.build(),
            Err(SecurityBuildError::MissingUnmatchedPolicy)
        ));

        let mut duplicate = SecurityWeb::builder();
        duplicate.chain(chain("one", 1, Arc::new(ExactPathMatcher::new("/one")?))?)?;
        duplicate.chain(chain("two", 1, Arc::new(ExactPathMatcher::new("/two")?))?)?;
        duplicate.unmatched_policy(UnmatchedPolicy::Deny);
        assert!(matches!(
            duplicate.build(),
            Err(SecurityBuildError::DuplicatePriority)
        ));

        let mut shadowed = SecurityWeb::builder();
        shadowed.chain(chain(
            "broad",
            1,
            Arc::new(PathPrefixMatcher::new("/api")?),
        )?)?;
        shadowed.chain(chain(
            "narrow",
            2,
            Arc::new(ExactPathMatcher::new("/api/items")?),
        )?)?;
        shadowed.unmatched_policy(UnmatchedPolicy::Deny);
        assert!(matches!(
            shadowed.build(),
            Err(SecurityBuildError::ShadowedChain)
        ));
        Ok(())
    }

    #[test]
    fn chain_requires_failure_handlers_and_unique_stage_ids() -> Result<(), Box<dyn Error>> {
        let mut missing = SecurityChain::builder(
            SecurityComponentId::new("missing-handlers")?,
            1,
            Arc::new(AnyRequest),
        );
        missing.authorization_manager(Arc::new(PermitAll));
        assert!(matches!(
            missing.build(),
            Err(SecurityBuildError::MissingAuthenticationEntryPoint)
        ));

        struct MissingExtractor;
        impl CredentialExtractor for MissingExtractor {
            fn extract(
                &self,
                _source: CredentialSource<'_>,
            ) -> Result<CredentialExtraction, CredentialExtractionFailure> {
                Ok(CredentialExtraction::Missing)
            }
        }
        let mut duplicate = SecurityChain::builder(
            SecurityComponentId::new("duplicate-stage")?,
            2,
            Arc::new(AnyRequest),
        );
        let id = SecurityComponentId::new("extractor")?;
        duplicate.credential_extractor(id.clone(), Arc::new(MissingExtractor))?;
        assert!(matches!(
            duplicate.credential_extractor(id, Arc::new(MissingExtractor)),
            Err(SecurityBuildError::DuplicateStage)
        ));
        Ok(())
    }
}
