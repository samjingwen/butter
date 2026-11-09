use butter_web::native::http::{HeaderMap, Method, Uri, header, uri::Authority};
use std::{collections::HashSet, error::Error, fmt, str::FromStr, sync::Arc};

/// Non-secret request facts available to matchers and authorization policy.
///
/// Header values, query values and request bodies are deliberately absent.
/// Forwarding headers have no special meaning; the host is taken only from the
/// normalized URI authority or direct `Host` header accepted by the HTTP stack.
#[derive(Clone, Debug)]
pub struct RequestMetadata {
    method: Method,
    path: Arc<str>,
    host: Option<Authority>,
    header_names: HashSet<butter_web::native::http::HeaderName>,
}

impl RequestMetadata {
    pub(crate) fn from_parts(
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<Self, RequestIntegrityFailure> {
        if headers
            .get_all(header::AUTHORIZATION)
            .iter()
            .nth(1)
            .is_some()
        {
            return Err(RequestIntegrityFailure::AmbiguousAuthorization);
        }
        let header_host = single_host(headers)?;
        let uri_host = uri
            .authority()
            .map(normalize_authority)
            .transpose()
            .map_err(|_| RequestIntegrityFailure::InvalidHost)?;
        if header_host.is_some() && uri_host.is_some() && header_host != uri_host {
            return Err(RequestIntegrityFailure::ConflictingHost);
        }
        Ok(Self {
            method: method.clone(),
            path: Arc::from(uri.path()),
            host: uri_host.or(header_host),
            header_names: headers.keys().cloned().collect(),
        })
    }

    /// Returns the normalized HTTP method.
    #[must_use]
    pub const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the normalized, non-decoded URI path without a query.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the validated direct authority, including a port when supplied.
    #[must_use]
    pub const fn host(&self) -> Option<&Authority> {
        self.host.as_ref()
    }

    /// Reports whether a header name was present without exposing its value.
    #[must_use]
    pub fn has_header(&self, name: &butter_web::native::http::HeaderName) -> bool {
        self.header_names.contains(name)
    }
}

fn single_host(headers: &HeaderMap) -> Result<Option<Authority>, RequestIntegrityFailure> {
    let mut hosts = headers.get_all(header::HOST).iter();
    let first = hosts.next();
    if hosts.next().is_some() {
        return Err(RequestIntegrityFailure::InvalidHost);
    }
    first
        .map(|value| {
            value
                .to_str()
                .map_err(|_| RequestIntegrityFailure::InvalidHost)
                .and_then(|value| {
                    Authority::from_str(&value.to_ascii_lowercase())
                        .map_err(|_| RequestIntegrityFailure::InvalidHost)
                })
        })
        .transpose()
}

pub(crate) fn normalize_authority(
    authority: &Authority,
) -> Result<Authority, butter_web::native::http::uri::InvalidUri> {
    Authority::from_str(&authority.as_str().to_ascii_lowercase())
}

/// Request-integrity rejection detected before chain selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestIntegrityFailure {
    /// More than one `Authorization` field was presented.
    AmbiguousAuthorization,
    /// The direct host authority was malformed or repeated.
    InvalidHost,
    /// URI authority and direct `Host` header disagreed.
    ConflictingHost,
}

impl fmt::Display for RequestIntegrityFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("request integrity validation failed")
    }
}

impl Error for RequestIntegrityFailure {}
