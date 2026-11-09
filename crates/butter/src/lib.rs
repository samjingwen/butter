//! Rust application development, smooth like butter.
//!
//! Defaults select core only. Explicit `web` enables HTTP startup and routing.
//! Optional `security`, `actuator`, `data` and `workflow` select application
//! security, operational health, PostgreSQL and durable persistence.
//! Features alone expose no routes or security policy.
//! Applications keep their own domain models, authorization and business policy.

#[cfg(feature = "actuator")]
pub use butter_actuator as actuator;
#[cfg(feature = "web")]
pub use butter_boot::{Application, RunningApplication};
pub use butter_core as core;
#[cfg(feature = "data")]
pub use butter_data as data;
#[cfg(feature = "security")]
pub use butter_security as security;
#[cfg(feature = "web")]
pub use butter_web as web;
#[cfg(feature = "workflow")]
pub use butter_workflow as workflow;
