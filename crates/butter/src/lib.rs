//! Rust application development, smooth like butter.
//!
//! The default `web` feature exposes `Application` and protected HTTP routing.
//! Optional `data` and `workflow` features select PostgreSQL and durable persistence.
//! Applications keep their own domain models, authorization and business policy.

#[cfg(feature = "web")]
pub use butter_boot::{Application, RunningApplication};
pub use butter_core as core;
#[cfg(feature = "data")]
pub use butter_data as data;
#[cfg(feature = "web")]
pub use butter_web as web;
#[cfg(feature = "workflow")]
pub use butter_workflow as workflow;
