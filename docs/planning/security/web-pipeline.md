# Web security pipeline

## Purpose

The web security package composes request security as one validated boundary around application routes.
It uses native Axum handlers and Tower services rather than maintaining another HTTP implementation.

## Request normalization

Security matching and credential extraction operate only on the normalized request accepted by the underlying HTTP stack.
The boundary rejects malformed paths, invalid hosts, ambiguous authorization headers and conflicting credential presentations before application routing.
It does not duplicate parsing protections already guaranteed by Hyper or Axum, but it documents and tests the guarantees on which matchers rely.

Forwarded client identity is trusted only through an explicit proxy configuration.
The default ignores forwarding headers and uses the directly connected peer where available.

## Request matcher

A request matcher can inspect:

- Normalized path.
- HTTP method.
- Validated host.
- Presence of a selected non-secret header.
- A composition of other matchers.

Matcher results are deterministic and side-effect free.
Matchers do not read request bodies or perform database calls.

## Multiple chains

The security-chain proxy evaluates chains in explicit order and invokes only the first match.
Each chain can select different credential mechanisms, context repositories, exploit protection, entry points and authorization policies.

Construction rejects duplicate priorities and obvious broad-before-narrow shadowing where the matcher model can prove it.
The builder requires an explicit final unmatched policy.
The recommended final policy denies every unmatched request.

## Ordered stages

Consumers extend the pipeline relative to named semantic stages rather than raw numeric positions.
The initial stage anchors are:

- Request integrity.
- Context load.
- Exploit protection.
- Credential extraction.
- Authentication.
- Session transition.
- Authorization.
- Application invocation.
- Context persistence.
- Response completion.

The builder rejects duplicate extension identifiers, impossible dependencies and placement that moves authorization before authentication.
Mandatory request cleanup and exception translation cannot be replaced by application extensions.

## Exception translation

Exception translation maps typed security failures into the configured response strategy.
It clears any uncommitted authentication result before requesting credentials or denying access.

An authentication entry point may return `401`, attach `WWW-Authenticate`, or redirect to an application login route.
An access-denied handler normally returns `403` or an application-owned error page.
Redirect targets must pass explicit allow-list validation owned by the application.

## Security headers

The web package should offer composable policies for:

- `X-Content-Type-Options`.
- Referrer policy.
- Frame restrictions.
- Permissions policy.
- Cache control for sensitive responses.
- Strict transport security when the request is known to be secure.

Content Security Policy remains application-specific because a generic value can break or weaken real applications.
Strict transport security is not emitted based on untrusted forwarding headers.

## CORS

CORS processing must run before authentication responses need browser-visible headers.
Butter may integrate a proven Tower CORS layer but does not invent a second CORS engine.
The application supplies the origin, method, header and credential policy.
Wildcard origins combined with browser credentials are rejected.

## Probes

Butter's current `/live` and `/ready` probes remain owned by the protected HTTP boundary until the proposed Actuator transition is implemented.
The [Actuator plan](../actuator/README.md) would replace them with protected `/actuator/health` routes and retain minimal disclosure.
Security-chain integration must not let an application replace whichever framework health routes the accepted implementation owns.

## Safe diagnostics

At startup the framework may emit a safe chain inventory containing matcher summaries, enabled mechanism names and stage identifiers.
Per-request trace diagnostics may identify which stage rejected a request.
Neither diagnostic form includes credentials, cookies, tokens, request bodies or sensitive query values.
