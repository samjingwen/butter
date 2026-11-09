use crate::{
    AccessDeniedHandler, AuthenticationEntryPoint, CredentialExtraction,
    CredentialExtractionFailure, CredentialExtractor, CredentialSource, MatcherDescriptor,
    NeutralAccessDeniedHandler, NeutralAuthenticationEntryPoint, RequestMatcher, RequestMetadata,
    WebAuthenticationFailure, matcher::descriptor_covers, response::empty_response,
};
use butter_security::{
    AuthenticationManager, AuthorizationFailure, AuthorizationManager, SecurityContext, authorize,
};
use butter_web::{
    Router,
    native::{
        extract::{Request, State},
        http::StatusCode,
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
                next.run(request).await
            }
        };
    };

    let source = CredentialSource::new(request.method(), request.uri(), request.headers());
    let context = match authenticate(chain, source).await {
        Ok(context) => context,
        Err(AuthenticationStepFailure::Extraction(failure)) => {
            return chain
                .entry_point
                .commence(&metadata, WebAuthenticationFailure::Extraction(failure))
                .await;
        }
        Err(AuthenticationStepFailure::Authentication(failure)) => {
            return chain
                .entry_point
                .commence(&metadata, WebAuthenticationFailure::Authentication(failure))
                .await;
        }
    };
    match authorize(chain.authorization_manager.as_ref(), &context, &metadata).await {
        Ok(()) => {
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Err(failure @ (AuthorizationFailure::Denied | AuthorizationFailure::NoGrant))
            if !context.is_authenticated() =>
        {
            let _ = failure;
            chain
                .entry_point
                .commence(&metadata, WebAuthenticationFailure::MissingCredentials)
                .await
        }
        Err(failure) => chain.denied_handler.denied(&metadata, failure).await,
    }
}

async fn authenticate(
    chain: &SecurityChain,
    source: CredentialSource<'_>,
) -> Result<SecurityContext, AuthenticationStepFailure> {
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
        return Ok(SecurityContext::anonymous());
    };
    let Some(manager) = chain.authentication_manager.as_ref() else {
        return Err(AuthenticationStepFailure::Authentication(
            butter_security::AuthenticationFailure::Operational(
                butter_security::AuthenticationOperationalError::Internal,
            ),
        ));
    };
    match manager.authenticate(authentication_request.as_ref()).await {
        Ok(authentication) => Ok(authentication.into_context()),
        Err(failure) => Err(AuthenticationStepFailure::Authentication(failure)),
    }
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
