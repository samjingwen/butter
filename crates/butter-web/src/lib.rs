//! Protected HTTP routing with native Axum handler interoperability.
//!
//! [`Router`] preserves route inventory for bootstrap admission and probe checks.
//! [`native`] is Axum itself, not an independently maintained HTTP implementation.

pub use axum as native;
pub use axum::{extract, response, routing};
mod public_reads;

/// Validated upstream browser transport primitives used by higher-level adapters.
///
/// The unchecked cookie reader is exported here only for adapters, such as
/// `butter-security-web`, that own mutation protection for the same request.
pub mod browser {
    pub use batter_axum::browser::*;
    pub use batter_axum::low_level::read_unchecked_cookie;
}

pub use batter_axum::{
    AdmittedRequest, BoundaryAssemblyError, GuardedRouter as Router, HttpBoundary, ProbePath,
    ReadinessPolicy, RequestPolicy, ResponseConstructionBudget, RouteInventory,
};
pub use public_reads::{PublicReadError, PublicReadHttp, PublicReadSubtree};
