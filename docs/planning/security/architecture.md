# Butter Security architecture

## Design principle

Reuse proven cryptographic and protocol libraries, keep application policy explicit, and let Butter own sequencing that must always be correct.
Spring Security supplies the architectural reference for context, provider, authorization and filter-chain seams.
Rust ownership, async execution, typed construction and explicit dependencies determine Butter's implementation shape.

Butter Security is application-security infrastructure rather than an identity provider.
It protects an application's entry points and service boundaries without owning the application's users, tenants, credentials, keys or business permissions.

## Proposed packages

### `butter-security`

The core package owns protocol-independent security types and traits.
It defines authentication requests and results, principals, authorities, security context, authentication managers and providers, authorization managers, decisions, handlers and security events.
It does not depend on Axum, Tower, SQLx, cookies, JWT libraries or a persistence driver.

### `butter-security-web`

The web package integrates core security contracts with `butter-web`, Axum and Tower.
It owns request matchers, security-chain selection, credential extraction, request-scoped context, exception translation, exploit-protection composition and framework-validated stage ordering.
It must preserve Butter's existing HTTP admission, response-construction deadline, liveness, readiness and graceful-shutdown contracts.

### `butter-security-test`

The test package owns synthetic principals, request helpers, mock providers, CSRF helpers, response assertions and reusable contract suites.
It is intended for development dependencies and must not make unsafe production configuration convenient.

## Dependency direction

`butter-security` depends only on narrow foundational crates needed for async-safe types, secrecy and error contracts.
`butter-security-web` depends on `butter-security`, `butter-core` and `butter-web`.
`butter-security-test` depends on the public security packages and test-only HTTP utilities.
`butter-core` remains independent of every security package.
`butter-data` and `butter-workflow` remain independent of security.

An application may combine security with data, but Butter must not create a hidden dependency from authentication into PostgreSQL.

## Security context

The security context is immutable after successful authentication and belongs to one request.
It contains authenticated identity, authorities, assurance information and non-secret details required for policy decisions.
It never contains raw passwords, bearer tokens, session identifiers or API key values.

The web integration stores the context in request extensions and exposes typed extractors.
It does not use thread-local state because asynchronous Rust tasks can move between executor threads.
Detached tasks do not inherit identity implicitly.
An application must clone and pass an explicitly approved context when background work genuinely needs caller identity.

## Security-chain proxy

One top-level security layer selects the first configured chain whose request matcher accepts the normalized request.
Each chain owns an isolated set of mechanisms and policies.
The framework rejects ambiguous ordering, duplicate mandatory stages and configurations that can leave unmatched requests accidentally public.

Public authorization means that a request does not require an authenticated principal.
It does not bypass request normalization, safe headers, diagnostics or applicable exploit protection.
A full security bypass is a separate exceptional operation and is not part of the initial public API.

## Framework-owned ordering

The validated pipeline establishes these logical phases:

1. Request integrity and normalization.
2. Security-chain selection.
3. Existing context loading.
4. Exploit protection and response-header preparation.
5. Credential extraction.
6. Authentication.
7. Session strategy and context transition.
8. Authorization.
9. Application invocation.
10. Explicit context persistence and security-event completion.

Exception translation surrounds the phases that can reject authentication or authorization.
Request-owned sensitive material is dropped on every completion path, including cancellation and errors.

## Build-time validation

Security configuration is inert until built and performs no I/O during construction.
The build step validates chain precedence, mandatory stages, route fallback, credential collision policy, CSRF decisions and handler completeness before a listener is bound.
Invalid security composition is a startup error rather than a runtime warning.

The built plan has a safe diagnostic representation that lists chain matchers, mechanisms and stage names without including credentials or application secrets.

## Application boundary

Applications implement identity lookup, password verification, token verification, session persistence and domain authorization through public extension contracts.
Applications remain responsible for durable audit records, abuse controls, tenant isolation and recovery policy.
Butter provides no user table, role table, session table, token format, signing-key store or KMS integration.

## Deliberate differences from Spring Security

- Butter uses request ownership rather than a thread-local context holder.
- Butter separates credential input from authenticated output instead of using one mutable authentication object for both states.
- Butter uses explicit builders and traits rather than bean discovery or global configuration.
- Butter uses explicit service guards rather than annotation-driven method interception.
- Butter does not generate a default user, password or login page.
- Butter does not silently enable a database or identity provider.
