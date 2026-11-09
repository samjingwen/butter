use butter_security::{AuthenticationMechanism, AuthenticationRequest, CredentialRequest};
use butter_web::native::http::{HeaderMap, Method, Uri, header};
use std::{error::Error, fmt};
use zeroize::Zeroize;

const MAX_CONFIGURED_CREDENTIAL_BYTES: usize = 16 * 1_024;

/// Bounded view available to credential extractors.
///
/// Unlike [`crate::RequestMetadata`], this view exposes header values because
/// credential adapters must deliberately consume them. It never exposes the
/// request body or request extensions.
#[derive(Clone, Copy)]
pub struct CredentialSource<'a> {
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
}

impl<'a> CredentialSource<'a> {
    pub(crate) const fn new(method: &'a Method, uri: &'a Uri, headers: &'a HeaderMap) -> Self {
        Self {
            method,
            uri,
            headers,
        }
    }

    /// Returns the normalized method.
    #[must_use]
    pub const fn method(self) -> &'a Method {
        self.method
    }

    /// Returns the normalized URI.
    #[must_use]
    pub const fn uri(self) -> &'a Uri {
        self.uri
    }

    /// Returns request headers for deliberate credential parsing.
    #[must_use]
    pub const fn headers(self) -> &'a HeaderMap {
        self.headers
    }
}

/// Result of one credential extractor.
pub enum CredentialExtraction {
    /// The extractor's credential family was absent.
    Missing,
    /// Exactly one bounded credential request was extracted.
    Present(Box<dyn AuthenticationRequest>),
}

impl fmt::Debug for CredentialExtraction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "CredentialExtraction::Missing",
            Self::Present(_) => "CredentialExtraction::Present([REDACTED])",
        })
    }
}

/// Sanitized credential presentation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialExtractionFailure {
    /// Credential syntax was malformed or repeated.
    Malformed,
    /// More than one configured credential family was presented.
    Ambiguous,
    /// A credential exceeded its configured byte limit.
    TooLarge,
}

impl fmt::Display for CredentialExtractionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential extraction failed")
    }
}

impl Error for CredentialExtractionFailure {}

/// Synchronous, bounded extraction of one credential family.
///
/// Extractors return `Missing` only when their family was not presented.
/// Recognized malformed input is terminal and must return an error.
pub trait CredentialExtractor: Send + Sync {
    /// Extracts at most one credential-bearing authentication request.
    fn extract(
        &self,
        source: CredentialSource<'_>,
    ) -> Result<CredentialExtraction, CredentialExtractionFailure>;
}

/// Validated maximum credential byte count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialLimit(usize);

impl CredentialLimit {
    /// Creates a non-zero limit no greater than 16 KiB.
    pub fn new(bytes: usize) -> Result<Self, CredentialExtractionFailure> {
        if bytes == 0 || bytes > MAX_CONFIGURED_CREDENTIAL_BYTES {
            return Err(CredentialExtractionFailure::TooLarge);
        }
        Ok(Self(bytes))
    }

    /// Returns the byte limit.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// Redacting, zeroizing bearer token bytes.
pub struct BearerToken(Vec<u8>);

impl BearerToken {
    /// Exposes token bytes only to a provider that recognizes this request type.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

impl Zeroize for BearerToken {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for BearerToken {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Strict RFC 6750 bearer credential extractor.
///
/// The adapter accepts exactly one `Authorization` field containing the
/// case-insensitive `Bearer` scheme, one ASCII space and bounded token68 bytes.
pub struct BearerTokenExtractor {
    mechanism: AuthenticationMechanism,
    limit: CredentialLimit,
}

impl BearerTokenExtractor {
    /// Creates an extractor for one application-selected mechanism.
    #[must_use]
    pub const fn new(mechanism: AuthenticationMechanism, limit: CredentialLimit) -> Self {
        Self { mechanism, limit }
    }
}

impl CredentialExtractor for BearerTokenExtractor {
    fn extract(
        &self,
        source: CredentialSource<'_>,
    ) -> Result<CredentialExtraction, CredentialExtractionFailure> {
        let mut values = source.headers().get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return Ok(CredentialExtraction::Missing);
        };
        if values.next().is_some() {
            return Err(CredentialExtractionFailure::Malformed);
        }
        let bytes = value.as_bytes();
        if bytes.len() < 6 || !bytes[..6].eq_ignore_ascii_case(b"bearer") {
            return Ok(CredentialExtraction::Missing);
        }
        if bytes.get(6) != Some(&b' ') || bytes.len() == 7 || bytes.get(7) == Some(&b' ') {
            return Err(CredentialExtractionFailure::Malformed);
        }
        let token = &bytes[7..];
        if token.len() > self.limit.get() {
            return Err(CredentialExtractionFailure::TooLarge);
        }
        if !valid_token68(token) {
            return Err(CredentialExtractionFailure::Malformed);
        }
        Ok(CredentialExtraction::Present(Box::new(
            CredentialRequest::new(self.mechanism.clone(), BearerToken(token.to_vec())),
        )))
    }
}

fn valid_token68(token: &[u8]) -> bool {
    let padding = token
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(token.len());
    padding > 0
        && token[..padding].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && token[padding..].iter().all(|byte| *byte == b'=')
}

#[cfg(test)]
mod tests {
    use super::*;
    use butter_web::native::http::{HeaderValue, Method, Uri};

    #[test]
    fn bearer_extraction_is_strict_and_redacted() {
        let extractor = BearerTokenExtractor::new(
            AuthenticationMechanism::new("bearer").expect("mechanism"),
            CredentialLimit::new(16).expect("limit"),
        );
        let uri = Uri::from_static("/");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer private-token"),
        );
        let extracted = extractor
            .extract(CredentialSource::new(&Method::GET, &uri, &headers))
            .expect("extract");
        assert_eq!(
            format!("{extracted:?}"),
            "CredentialExtraction::Present([REDACTED])"
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer  two"),
        );
        assert!(matches!(
            extractor.extract(CredentialSource::new(&Method::GET, &uri, &headers)),
            Err(CredentialExtractionFailure::Malformed)
        ));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer ="));
        assert!(matches!(
            extractor.extract(CredentialSource::new(&Method::GET, &uri, &headers)),
            Err(CredentialExtractionFailure::Malformed)
        ));
    }
}
