//! Protected HTTP routing with native Axum handler interoperability.
//!
//! [`Router`] preserves route inventory for bootstrap admission and probe checks.
//! [`native`] is Axum itself, not an independently maintained HTTP implementation.

pub use axum as native;
pub use axum::{extract, response, routing};
pub use batter_axum::{
    AdmittedRequest, BoundaryAssemblyError, GuardedRouter as Router, HttpBoundary, ProbePath,
    ReadinessPolicy, RequestPolicy, ResponseConstructionBudget,
};
