# Threat model

## Scope

This threat model covers generic application-security composition provided by Butter.
It does not describe any downstream product, deployment, user population or private incident.

## Protected assets

- Credential confidentiality.
- Correct authenticated identity.
- Correct authorization decisions.
- Session integrity and revocation behavior.
- CSRF token confidentiality and validation.
- Security-chain configuration integrity.
- Isolation between concurrent requests.
- Neutral error behavior.
- Availability under bounded malformed input.

## Trust boundaries

- Untrusted network input entering Hyper and Axum.
- Forwarded metadata crossing a configured reverse-proxy boundary.
- Credential extractors handing requests to providers.
- Providers calling application identity stores or external verifiers.
- Security context entering application handlers and service policy.
- Context repositories persisting session state.
- Application extensions entering framework-owned stage ordering.

## Primary threats

### Authentication confusion

An attacker presents multiple credential forms or exploits provider fallback to obtain a weaker identity.
Butter rejects conflicting credentials by default and treats recognized-but-invalid credentials as terminal.

### Authorization omission

An unmatched route or all-abstain policy accidentally becomes public.
Butter requires an explicit unmatched policy and denies all-abstain decisions.

### Context leakage

Identity from one request leaks into another concurrent request or detached task.
Butter uses request-owned context and no thread-local or global holder.

### Filter-order bypass

An extension runs authorization before authentication, skips CSRF or bypasses mandatory cleanup.
Butter validates semantic stage dependencies and protects mandatory stages from replacement.

### Session fixation and replay

An attacker preserves a pre-authentication session identifier or reuses invalidated state.
Stateful authentication rotates identifiers and delegates revocation and replay records to the application repository.

### Cross-site request forgery

A browser automatically attaches an authentication cookie to an attacker-controlled unsafe request.
Cookie-authenticated chains require an explicit CSRF policy, token validation and configured origin checks.

### Proxy spoofing

An attacker supplies forwarding headers to influence origin, scheme, host or network policy.
Forwarded metadata is ignored unless the directly connected peer belongs to configured trusted proxies.

### Secret disclosure

Credentials enter logs, errors, debug output, events or panic messages.
Credential types redact output, diagnostics use reason codes and tests scan representative formatting paths.

### Resource exhaustion

An attacker supplies oversized credentials, expensive provider input or high-cardinality policy data.
Extractors bound input, operations inherit deadlines and cancellation, and adapters document computational limits.

## Out-of-scope threats

Butter cannot protect an application that deliberately logs credentials, grants broad database privileges, implements incorrect provider logic or ignores authorization results.
Butter does not replace network denial-of-service protection, operating-system isolation, database security, KMS policy or application incident response.

## Security defaults

- Deny unmatched requests.
- Deny all-abstain authorization.
- Reject ambiguous credentials.
- Reject incomplete cookie-authentication CSRF configuration.
- Ignore untrusted forwarding headers.
- Keep credentials out of authenticated results.
- Keep security context request-scoped.
- Fail startup on invalid stage ordering.

## Phase 2 verification evidence

Synthetic loopback acceptance covers first-match public, authenticated and authority-specific chains.
It covers malformed and duplicate authorization fields, conflicting bearer and API-key presentations, neutral rejected-credential responses, unmatched denial and encoded path separation.
Concurrent requests prove that different principals remain isolated in request extensions.
An outer response deadline drops an active authentication future without invoking the application handler.
The same acceptance proves that application security stays inside Butter admission while explicitly attached Actuator reads remain outside application chains and graceful shutdown still releases the listener.

## Phase 3 verification evidence

Synthetic loopback acceptance covers route-driven login, authenticated context loading, CSRF-protected mutation, explicit token re-exposure, session and token refresh, logout, stale-identifier replay and simultaneous cookie/bearer rejection.
It proves that refresh makes the previous identifier and token unusable and that logout invalidates server state before browser-cookie expiration is emitted.
An unconfirmed save and a post-persistence cookie-construction conflict both return a neutral failure without exposing the new identifier; retained test state demonstrates why neither response proves rollback or client receipt.
An outer response deadline drops active context loading without invoking the application handler.
Cookie parsing and serialization reuse the pinned upstream browser transport, while Butter owns the corresponding CSRF and persistence sequencing.

## Review cadence

The threat model is reviewed before each new authentication mechanism, persistence adapter or pipeline extension.
Every security defect receives a generic regression test before its fix is considered complete.
Confidential downstream evidence follows the separate public-repository boundary and never enters this document.
