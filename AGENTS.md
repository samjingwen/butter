# Butter

## Purpose

Build a cohesive Rust application framework inspired by Spring Boot's startup experience.
Prefer upstream dependencies; maintain source locally only for a justified fix or extension.
Reuse mechanisms, keep application policy explicit, and enforce important ordering through library-owned execution.

## Ownership

- `crates/butter`: feature-selected public facade and runnable example.
- `crates/butter-core`: upstream lifecycle, settings and operation primitives.
- `crates/butter-actuator`: transport-independent health aggregation and supervised contributor plans.
- `crates/butter-web`: protected HTTP composition and native Axum interoperability.
- `crates/butter-boot`: consuming application bootstrap through checked shutdown.
- `crates/butter-data`: upstream PostgreSQL transaction and session capabilities.
- `crates/butter-workflow`: durable-work persistence and atomic completion.
- `provenance/`: upstream provenance, retained licenses and canonical migration fixtures, not an extra framework component.

## Invariants

Keep core independent of Actuator, web, data and workflow, and web independent of Actuator.
Do not implement another async runtime, database engine, queue or identity provider.
An upstream dependency and a maintained source import are different ownership choices, not interchangeable branding.
Retain upstream licenses, provenance and failure tests when adopting source.
Do not rewrite applied SQL migrations or hand-edit SQLx metadata and Cargo.lock.
Keep application-specific policy, provider identities, credentials and product names out of this framework.
No global tracing subscriber or automatic database provisioning belongs in the library.
Document what cancellation and unconfirmed commit do not prove.

## Commands

- `bash scripts/check.sh`: formatting, strict Clippy, ordinary package tests, doctests and rustdoc.
- `python3 scripts/test-worktree-cache.py`: native Worktrunk cache-policy regression tests.
- `bash scripts/check-linux.sh`: ordinary quality and Worktrunk cache tests in pinned Ubuntu 24.04 `linux/amd64`.
- `bash scripts/check-workflow.sh`: imported persistence tests against owned disposable PostgreSQL 18 through Docker.
- `cargo run -p butter --example hello --features web,actuator`: local loopback HTTP example.

## Delivery

Follow this repository's [change delivery policy](.opencode/instructions/change-delivery.md), not a parent-workspace delivery file.
Do not initialize or restore the retired no-mistakes gate or its configuration.
Use an isolated Worktrunk worktree, verify the actual source graph and review the intended diff before committing.
No crates.io publication or deployment is configured or authorized by the bootstrap.
The bootstrap targets Linux and macOS; do not claim platform validation without executed evidence.
