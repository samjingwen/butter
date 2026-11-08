//! A narrow extension over upstream inventories and protected serving.
use crate::{BoundaryAssemblyError, HttpBoundary, ProbePath, RequestPolicy, Router};
use axum::{
    extract::Request,
    http::{StatusCode, request::Parts},
    middleware,
    response::Response,
    routing::{any, get},
};
use batter_axum::{RouteGroup, low_level};
use butter_core::{RegistrationError, registration::RegistrationTarget};
use std::{error::Error, fmt, sync::Arc};

/// Invalid public read configuration, without rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicReadError {
    /// A root subtree would reserve every application path.
    RootSubtree,
    /// The literal read path must be inside its reserved subtree.
    OutsideSubtree,
    /// A read was already assigned to the same literal path.
    DuplicatePath,
}
impl fmt::Display for PublicReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootSubtree => "public read subtree cannot be root",
            Self::OutsideSubtree => "public read path is outside its subtree",
            Self::DuplicatePath => "duplicate public read path",
        })
    }
}
impl Error for PublicReadError {}

/// Explicit read-only routes outside application admission, reserving a subtree.
///
/// Readers must perform bounded synchronous in-memory work only. This mechanism
/// assigns no operational meaning, dependency policy or authentication to a path.
/// Unknown subtree paths return 404; GET routes get Axum's ordinary bodyless HEAD
/// and method-not-allowed behavior. The application owns no routes in this subtree.
///
/// ```
/// use butter_web::{ProbePath, PublicReadSubtree};
/// use butter_web::native::{http::StatusCode, response::IntoResponse};
/// let reads = PublicReadSubtree::new(ProbePath::new("/status")?)?
///     .read(ProbePath::new("/status/summary")?, |_| StatusCode::OK.into_response())?;
/// # let _ = reads;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use = "assemble and register the public read boundary"]
pub struct PublicReadSubtree {
    root: ProbePath,
    paths: Vec<ProbePath>,
    reads: axum::Router,
}

impl PublicReadSubtree {
    /// Reserve a validated non-root literal subtree without binding or spawning.
    pub fn new(root: ProbePath) -> Result<Self, PublicReadError> {
        if root.as_str() == "/" {
            return Err(PublicReadError::RootSubtree);
        }
        Ok(Self {
            root,
            paths: Vec::new(),
            reads: axum::Router::new(),
        })
    }

    /// Add a literal GET/HEAD operation. No application body or asynchronous
    /// probe factory is supplied to the synchronous renderer.
    pub fn read<F>(mut self, path: ProbePath, read: F) -> Result<Self, PublicReadError>
    where
        F: Fn(&Parts) -> Response + Send + Sync + 'static,
    {
        let root = self.root.as_str();
        if path != self.root
            && !path
                .as_str()
                .strip_prefix(root)
                .is_some_and(|s| s.starts_with('/'))
        {
            return Err(PublicReadError::OutsideSubtree);
        }
        if self.paths.contains(&path) {
            return Err(PublicReadError::DuplicatePath);
        }
        self.paths.push(path);
        let read = Arc::new(read);
        self.reads = self.reads.route(
            path.as_str(),
            get(move |request: Request| {
                let read = read.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    drop(body);
                    read(&parts)
                }
            }),
        );
        Ok(self)
    }

    /// Validate application inventory against the entire subtree before serving.
    ///
    /// Upstream group overlap validation checks exact, nested, captured and
    /// wildcard routes without polling application handlers. A validation-only
    /// group marks the reserved subtree in the upstream boundary. The outer
    /// public router owns those paths; all other paths dispatch through the
    /// sealed upstream client, preserving admission and its response deadline.
    /// Each public route has an upstream operational observer; application paths
    /// retain their upstream observer after their own routing has matched the
    /// correct template. No bare assembled router escapes.
    pub async fn assemble(
        self,
        policy: RequestPolicy,
        application: Router,
    ) -> Result<PublicReadHttp, BoundaryAssemblyError> {
        let root = self.root.as_str();
        let trailing_root = format!("{root}/");
        let wildcard = format!("{root}/{{*public_read_path}}");
        let reserved = Router::new()
            .route(root, any(|| async { StatusCode::NOT_FOUND }))
            .route(&trailing_root, any(|| async { StatusCode::NOT_FOUND }))
            .route(&wildcard, any(|| async { StatusCode::NOT_FOUND }));
        let assembled = HttpBoundary::new(policy.clone())
            .with_group(RouteGroup::new("public.reads", policy, reserved))
            .expect("fixed group has a valid unique name and no fallback")
            .assemble(application)
            .await?;
        let client = assembled.in_process();
        let mut router = self.reads;
        if !self.paths.contains(&self.root) {
            router = router.route(root, any(|| async { StatusCode::NOT_FOUND }));
        }
        router = router
            .route(&trailing_root, any(|| async { StatusCode::NOT_FOUND }))
            .route(&wildcard, any(|| async { StatusCode::NOT_FOUND }))
            .route_layer(middleware::from_fn(low_level::operational_http))
            .fallback(move |request: Request| {
                let client = client.clone();
                async move { client.request(request).await }
            });
        Ok(PublicReadHttp { router })
    }
}

/// Sealed public/application composition, consumable only by protected serving.
///
/// ```compile_fail,E0599
/// fn cannot_extract(http: butter_web::PublicReadHttp) {
///     let _router = http.into_router();
/// }
/// ```
#[must_use = "register this boundary in protected startup"]
pub struct PublicReadHttp {
    router: axum::Router,
}

impl PublicReadHttp {
    /// Transfer the boundary and listener to the existing supervisor's HTTP driver.
    pub fn register_in<T: RegistrationTarget + ?Sized>(
        self,
        target: &mut T,
        name: &'static str,
        listener: impl axum::serve::Listener<Addr: fmt::Debug>,
    ) -> Result<(), RegistrationError> {
        low_level::register_http_in(target, name, listener, self.router)
    }
}
