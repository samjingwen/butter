use crate::{RequestMetadata, request::normalize_authority};
use butter_web::native::http::{HeaderName, Method, uri::Authority};
use std::{error::Error, fmt, str::FromStr, sync::Arc};

const MAX_PATH_BYTES: usize = 4_096;
const MAX_COMPOSITE_MATCHERS: usize = 64;

/// Safe structural description used for startup inventory and shadow checks.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MatcherDescriptor {
    /// Every normalized request.
    Any,
    /// One exact path.
    ExactPath(Arc<str>),
    /// A path segment subtree.
    PathPrefix(Arc<str>),
    /// One exact HTTP method.
    Method(Method),
    /// One normalized direct authority.
    Host(Authority),
    /// Presence of one header name, never its value.
    HeaderPresent(HeaderName),
    /// Every child matcher must match.
    All(Vec<Self>),
    /// At least one child matcher must match.
    AnyOf(Vec<Self>),
    /// Logical negation. Shadow analysis treats this conservatively.
    Not(Box<Self>),
    /// An application matcher without a provable structural relation.
    Custom,
}

/// Deterministic, side-effect-free request selector.
pub trait RequestMatcher: Send + Sync {
    /// Evaluates only normalized, non-secret request metadata.
    fn matches(&self, request: &RequestMetadata) -> bool;

    /// Describes built-in structure for diagnostics and conservative validation.
    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::Custom
    }
}

/// Matcher that selects every request.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnyRequest;

impl RequestMatcher for AnyRequest {
    fn matches(&self, _request: &RequestMetadata) -> bool {
        true
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::Any
    }
}

/// Invalid matcher construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatcherBuildError {
    /// A path was empty, not absolute or exceeded the path bound.
    InvalidPath,
    /// A host authority was invalid.
    InvalidHost,
    /// A composite had no child matchers.
    NoMatchers,
    /// A composite exceeded the child matcher bound.
    MatcherLimit,
}

impl fmt::Display for MatcherBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "invalid request matcher path",
            Self::InvalidHost => "invalid request matcher host",
            Self::NoMatchers => "request matcher composite requires a matcher",
            Self::MatcherLimit => "request matcher composite limit exceeded",
        })
    }
}

impl Error for MatcherBuildError {}

fn validated_path(path: impl Into<String>) -> Result<Arc<str>, MatcherBuildError> {
    let path = path.into();
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || !path.starts_with('/')
        || path.contains(['?', '#'])
    {
        return Err(MatcherBuildError::InvalidPath);
    }
    Ok(Arc::from(path))
}

/// Matcher for one exact normalized path.
#[derive(Clone, Debug)]
pub struct ExactPathMatcher(Arc<str>);

impl ExactPathMatcher {
    /// Validates an absolute path matcher.
    pub fn new(path: impl Into<String>) -> Result<Self, MatcherBuildError> {
        validated_path(path).map(Self)
    }
}

impl RequestMatcher for ExactPathMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        request.path() == &*self.0
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::ExactPath(Arc::clone(&self.0))
    }
}

/// Matcher for a normalized path segment subtree.
#[derive(Clone, Debug)]
pub struct PathPrefixMatcher(Arc<str>);

impl PathPrefixMatcher {
    /// Validates an absolute subtree root.
    pub fn new(path: impl Into<String>) -> Result<Self, MatcherBuildError> {
        let mut path = validated_path(path)?;
        if path.len() > 1 && path.ends_with('/') {
            let without_trailing_slash = &path[..path.len() - 1];
            if without_trailing_slash.ends_with('/') {
                return Err(MatcherBuildError::InvalidPath);
            }
            path = Arc::from(without_trailing_slash);
        }
        Ok(Self(path))
    }
}

impl RequestMatcher for PathPrefixMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        path_prefix_contains(&self.0, request.path())
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::PathPrefix(Arc::clone(&self.0))
    }
}

/// Matcher for one exact HTTP method.
#[derive(Clone, Debug)]
pub struct MethodMatcher(Method);

impl MethodMatcher {
    /// Creates an exact method matcher.
    #[must_use]
    pub const fn new(method: Method) -> Self {
        Self(method)
    }
}

impl RequestMatcher for MethodMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        request.method() == self.0
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::Method(self.0.clone())
    }
}

/// Matcher for one normalized direct authority.
#[derive(Clone, Debug)]
pub struct HostMatcher(Authority);

impl HostMatcher {
    /// Parses and normalizes a direct authority without trusting forwarding headers.
    pub fn new(host: &str) -> Result<Self, MatcherBuildError> {
        let authority = Authority::from_str(host).map_err(|_| MatcherBuildError::InvalidHost)?;
        normalize_authority(&authority)
            .map(Self)
            .map_err(|_| MatcherBuildError::InvalidHost)
    }
}

impl RequestMatcher for HostMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        request.host() == Some(&self.0)
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::Host(self.0.clone())
    }
}

/// Matcher for the presence of one header name without reading its value.
#[derive(Clone, Debug)]
pub struct HeaderPresentMatcher(HeaderName);

impl HeaderPresentMatcher {
    /// Creates a header-presence matcher.
    #[must_use]
    pub const fn new(name: HeaderName) -> Self {
        Self(name)
    }
}

impl RequestMatcher for HeaderPresentMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        request.has_header(&self.0)
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::HeaderPresent(self.0.clone())
    }
}

fn validate_composite(
    matchers: Vec<Arc<dyn RequestMatcher>>,
) -> Result<Vec<Arc<dyn RequestMatcher>>, MatcherBuildError> {
    if matchers.is_empty() {
        return Err(MatcherBuildError::NoMatchers);
    }
    if matchers.len() > MAX_COMPOSITE_MATCHERS {
        return Err(MatcherBuildError::MatcherLimit);
    }
    Ok(matchers)
}

/// Conjunction of a non-empty matcher list.
pub struct AllRequestMatcher(Vec<Arc<dyn RequestMatcher>>);

impl AllRequestMatcher {
    /// Validates a bounded matcher conjunction.
    pub fn new(matchers: Vec<Arc<dyn RequestMatcher>>) -> Result<Self, MatcherBuildError> {
        validate_composite(matchers).map(Self)
    }
}

impl RequestMatcher for AllRequestMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        self.0.iter().all(|matcher| matcher.matches(request))
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::All(self.0.iter().map(|matcher| matcher.descriptor()).collect())
    }
}

/// Disjunction of a non-empty matcher list.
pub struct AnyRequestMatcher(Vec<Arc<dyn RequestMatcher>>);

impl AnyRequestMatcher {
    /// Validates a bounded matcher disjunction.
    pub fn new(matchers: Vec<Arc<dyn RequestMatcher>>) -> Result<Self, MatcherBuildError> {
        validate_composite(matchers).map(Self)
    }
}

impl RequestMatcher for AnyRequestMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        self.0.iter().any(|matcher| matcher.matches(request))
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::AnyOf(self.0.iter().map(|matcher| matcher.descriptor()).collect())
    }
}

/// Logical negation of one matcher.
pub struct NotRequestMatcher(Arc<dyn RequestMatcher>);

impl NotRequestMatcher {
    /// Wraps one matcher.
    #[must_use]
    pub const fn new(matcher: Arc<dyn RequestMatcher>) -> Self {
        Self(matcher)
    }
}

impl RequestMatcher for NotRequestMatcher {
    fn matches(&self, request: &RequestMetadata) -> bool {
        !self.0.matches(request)
    }

    fn descriptor(&self) -> MatcherDescriptor {
        MatcherDescriptor::Not(Box::new(self.0.descriptor()))
    }
}

pub(crate) fn descriptor_covers(earlier: &MatcherDescriptor, later: &MatcherDescriptor) -> bool {
    if matches!(earlier, MatcherDescriptor::Any) {
        return true;
    }
    match later {
        MatcherDescriptor::All(children) => {
            if let MatcherDescriptor::All(required) = earlier {
                return required
                    .iter()
                    .all(|requirement| descriptor_covers(requirement, later));
            }
            children
                .iter()
                .any(|child| descriptor_covers(earlier, child))
        }
        MatcherDescriptor::AnyOf(children) => children
            .iter()
            .all(|child| descriptor_covers(earlier, child)),
        _ => match earlier {
            MatcherDescriptor::ExactPath(path) => {
                matches!(later, MatcherDescriptor::ExactPath(other) if path == other)
            }
            MatcherDescriptor::PathPrefix(prefix) => match later {
                MatcherDescriptor::ExactPath(path) | MatcherDescriptor::PathPrefix(path) => {
                    path_prefix_contains(prefix, path)
                }
                _ => false,
            },
            MatcherDescriptor::Method(method) => {
                matches!(later, MatcherDescriptor::Method(other) if method == other)
            }
            MatcherDescriptor::Host(host) => {
                matches!(later, MatcherDescriptor::Host(other) if host == other)
            }
            MatcherDescriptor::HeaderPresent(name) => {
                matches!(later, MatcherDescriptor::HeaderPresent(other) if name == other)
            }
            MatcherDescriptor::All(required) => required
                .iter()
                .all(|requirement| descriptor_covers(requirement, later)),
            MatcherDescriptor::AnyOf(options) => options
                .iter()
                .any(|option| descriptor_covers(option, later)),
            MatcherDescriptor::Any => true,
            MatcherDescriptor::Not(_) | MatcherDescriptor::Custom => false,
        },
    }
}

fn path_prefix_contains(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_shadow_proof_understands_subtrees_and_conjunctions() {
        let broad = MatcherDescriptor::PathPrefix(Arc::from("/api"));
        let narrow = MatcherDescriptor::All(vec![
            MatcherDescriptor::ExactPath(Arc::from("/api/items")),
            MatcherDescriptor::Method(Method::GET),
        ]);
        assert!(descriptor_covers(&broad, &narrow));
        assert!(!descriptor_covers(&narrow, &broad));
        assert!(!path_prefix_contains("/api", "/apix"));
        assert!(PathPrefixMatcher::new("/api/").is_ok());
        assert_eq!(
            PathPrefixMatcher::new("//").err(),
            Some(MatcherBuildError::InvalidPath)
        );
        assert_eq!(
            PathPrefixMatcher::new("/api//").err(),
            Some(MatcherBuildError::InvalidPath)
        );
    }
}
