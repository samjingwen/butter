//! Shared lifecycle, configuration and operation primitives.
//!
//! Butter uses the pinned upstream implementation rather than duplicating its
//! operational machinery. Applications normally start through `butter::Application`.

pub use batter_core::*;
