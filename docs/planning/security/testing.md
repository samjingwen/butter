# Testing

## Purpose

Butter Security needs reusable verification comparable in role to Spring Security Test while preserving real HTTP acceptance at the framework boundary.
Test helpers make secure scenarios concise without making production bypasses convenient.

## Test package

`butter-security-test` should provide:

- Synthetic principals and authorities.
- A deterministic authentication provider.
- Request helpers for bearer, cookie and API key credentials.
- Valid, missing and invalid CSRF helpers.
- Context repository fixtures.
- Assertions for status, challenges, denial categories and security headers.
- Contract suites for providers, repositories, managers and handlers.

Production packages must not expose a `set_current_user` shortcut or a header that bypasses authentication.
Test authentication is installed only by explicit test composition.

## Unit tests

Unit tests cover value validation, provider outcomes, authorization combinators, matcher composition, redaction and builder validation.
They include boundary lengths, invalid encodings, duplicate configuration and all-abstain decisions.

## Contract tests

Reusable contract suites verify:

- Providers do not retain or expose credentials.
- Rejected credentials do not fall through.
- Repositories distinguish missing, invalid, expired and operational failures internally.
- Session strategies rotate identifiers where required.
- Authorization managers obey documented abstain and short-circuit behavior.
- Entry points and denial handlers produce valid bounded responses.

## Real HTTP tests

Public acceptance uses a compiled or in-process Butter application over real loopback TCP.
It does not rely only on calling an Axum router as a pure function.

The suite covers public, authenticated and denied routes, multiple security chains, response headers, context persistence, logout, CSRF, listener shutdown and cancellation during admitted work.

## Concurrency and cancellation

Tests issue concurrent requests with different principals and prove that contexts never cross request boundaries.
They cancel authentication, authorization and context-repository futures and verify that no successful response or persisted context is invented.
They cover response loss after persistence separately from a confirmed persistence failure.

## Adversarial cases

The maintained matrix includes:

- Duplicate and malformed authorization headers.
- Simultaneous cookie and bearer credentials.
- Encoded and normalized path edge cases.
- Untrusted forwarding headers.
- Provider unsupported versus rejected behavior.
- Every provider unsupported.
- Every authorization manager abstaining.
- Broad matchers shadowing narrow chains.
- Missing CSRF token after login and logout.
- Session fixation attempts.
- Oversized credentials and bounded error bodies.
- Secret formatting through `Debug`, display and error sources.

## Compile and feature verification

The source graph check verifies minimal, core-security, web-security and all-feature graphs.
Core security must compile without Axum, SQLx, JOSE or workflow dependencies.
Rustdoc and doctests cover each public extension contract.

## External evidence boundaries

Tests use synthetic identities, routes, keys and configuration.
No private downstream repository, fixture, log, schema, endpoint or credential is copied into Butter.
Public CI never receives access to a confidential downstream consumer.
