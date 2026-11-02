//! Owned PostgreSQL operations, transaction scopes and session policy.
//!
//! SQLx remains native. This is not an ORM, a repository abstraction or a database
//! provisioner. Unconfirmed commits are not rollback proof or replay authority.

pub use batter_sqlx::*;
/// Native SQLx queries and driver types, sharing Butter's resolved dependency graph.
pub use sqlx as native;
