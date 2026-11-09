# Butter Security planning index

## Status

Phase 1 implements the transport-independent `butter-security` core.
Phase 2 implements the `butter-security-web` request-security spine and its explicit `butter-boot` attachment.
Phase 3 implements explicit stateful browser chains, session rotation and persistence ordering, host-only cookie transport, CSRF token repositories and handlers, and exact origin validation.
Together they provide credential-safe authentication contracts, immutable request-scoped contexts, ordered providers, first-match web chains, fail-closed authorization, neutral HTTP failures and stateful browser protection.
Dedicated reusable test support remains a planned later slice.
Enabling a security feature alone does not protect an HTTP route.
An application must build the policy and explicitly attach it through `Application::security`.

## Objective

Butter Security should provide the cohesive security composition and extension seams associated with Spring Security while remaining explicit, asynchronous and idiomatic in Rust.
The design takes architectural reference from Spring Security 7.1 without copying its Java dependency-injection, reflection, annotation or thread-local mechanisms.
The framework owns ordering and generic security mechanisms while consuming applications own identity data, credentials, authorization policy and product behavior.

## Accepted direction

- Use separate protocol-independent, web-integration and testing packages.
- Keep security core independent of Axum, SQLx, sessions, JWT libraries and application schemas.
- Keep security context request-scoped rather than thread-local or globally mutable.
- Separate credential-bearing authentication requests from credential-free authenticated results.
- Support ordered authentication providers with explicit authenticated, unsupported and rejected outcomes.
- Support composable authorization managers that fail closed when no policy grants access.
- Support multiple request-matched security chains with framework-validated ordering.
- Require an explicit CSRF decision for browser-managed credentials.
- Keep identity-provider, tenant, key-management and durable audit policy outside Butter.
- Keep confidential downstream consumer details out of this public repository.

## Documents

- [Architecture](architecture.md)
- [Authentication](authentication.md)
- [Authorization](authorization.md)
- [Web security pipeline](web-pipeline.md)
- [Sessions and CSRF](sessions-and-csrf.md)
- [Extension points](extension-points.md)
- [Threat model](threat-model.md)
- [Testing](testing.md)
- [Public repository boundary](public-repository-boundary.md)
- [Delivery roadmap](delivery-roadmap.md)

## Spring Security references

- Servlet security architecture: <https://docs.spring.io/spring-security/reference/servlet/architecture.html>
- Authentication architecture: <https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html>
- Authorization architecture: <https://docs.spring.io/spring-security/reference/servlet/authorization/architecture.html>
- CSRF architecture: <https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html>
- Security testing: <https://docs.spring.io/spring-security/reference/servlet/test/index.html>

The references were reviewed against Spring Security 7.1.2 on 2026-11-08.

## Remaining review questions

- Which security headers can be safe framework defaults and which must remain application policy.
- Which optional adapters demonstrate enough repeated demand to justify additional packages.

No public API should be stabilized until a real confidential consumer and a synthetic example have exercised the complete request path.
