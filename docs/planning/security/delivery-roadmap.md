# Butter Security delivery roadmap

## Delivery rule

The framework is delivered in reviewed vertical slices rather than one broad Spring Security reimplementation.
Each slice includes public contracts, synthetic examples, real HTTP acceptance and updated threat-model evidence.

## Phase 0: architecture acceptance

- Review this planning set.
- Confirm package boundaries and non-goals.
- Prototype generic and object-safe forms of the central traits without stabilizing them.
- Define safe dependency and disclosure policy for a security framework.

Acceptance requires a coherent request flow, explicit ownership boundaries and resolution of the open trait-shape questions.

## Phase 1: security core

Status: implemented by the first `butter-security` source slice, subject to its exact-head delivery gates and review.

- Add `butter-security`.
- Add credential request wrappers and credential-free authenticated results.
- Add principals, authorities and request-scoped security context.
- Add authentication manager and provider outcomes.
- Add authorization manager, decisions and combinators.
- Add typed errors and credential-free security events.

Acceptance requires provider fallback, terminal rejection, all-abstain denial, secret redaction, cancellation tests, rustdoc and isolated feature graphs.

## Phase 2: web security spine

Status: implemented by the `butter-security-web` source slice, subject to its exact-head delivery gates and review.

- Add `butter-security-web`.
- Add request matchers and first-match chain selection.
- Add named pipeline stages and build-time validation.
- Add credential extractor contracts.
- Add authentication entry points and access-denied handlers.
- Integrate with Butter HTTP admission, deadlines, probes and graceful shutdown.

Acceptance requires real loopback tests for multiple chains, malformed credentials, unmatched requests, context isolation and framework-owned ordering.

## Phase 3: stateful browser security

Status: implemented by the `butter-security-web` stateful browser slice, subject to its exact-head delivery gates and review.

- Add context repository and session strategy integration.
- Add secure cookie policy.
- Add session identifier rotation.
- Add CSRF token repository and request-handler contracts.
- Add origin validation and Angular-compatible SPA behavior.

Acceptance requires login, authenticated mutation, logout, token refresh, fixation rejection, CSRF rejection and persistence uncertainty tests.

## Phase 4: security test support

- Add `butter-security-test`.
- Add synthetic principal, provider, credential and CSRF helpers.
- Add reusable provider, repository and authorization contract suites.
- Add response and event assertions.

Acceptance requires downstream tests to express secure and denied paths without production bypass hooks.

## Phase 5: first consumer hardening

- Integrate one confidential consumer through immutable Butter revisions.
- Keep consumer-specific identity, key and tenant policy outside Butter.
- Generalize only mechanisms proven reusable by the integration.
- Fix framework gaps locally and publish sanitized Butter changes.

Acceptance requires both stateful and stateless chains, service authorization, real persistence integration and no confidential information in Butter history.

## Deferred adapters

Password hashing, JWT resource-server verification, SQLx session persistence, OAuth client support, WebSocket security, method macros, request caching, remember-me and post-invocation authorization are separate reviewed phases.
OAuth authorization-server behavior, identity-provider storage, signing-key lifecycle, tenant policy and application abuse controls are not Butter responsibilities.

## Maturity gate

Butter Security remains experimental and unpublished until:

- The central extension contracts survive a real consumer integration.
- Mandatory ordering and fail-closed defaults have adversarial tests.
- Public documentation describes cancellation, persistence uncertainty and secret handling.
- The documented macOS and pinned-Ubuntu local quality gates pass on the exact reviewed commit.
- The public-repository boundary has been reviewed against the complete diff.

No crate publication or compatibility promise is authorized by this plan.
