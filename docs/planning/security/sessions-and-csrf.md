# Sessions and CSRF

## Stateful and stateless security

Each security chain declares whether it loads and persists authentication context.
A stateless chain uses no context repository and authenticates every protected request from presented credentials.
A stateful chain uses an application-supplied context repository and a browser-safe session identifier.
Stateful behavior is inert until the chain explicitly installs a built `StatefulSecurity` plan.

Butter does not supply a hidden in-memory production session store.
An in-memory implementation may exist only as an explicitly test-oriented utility.

## Security context repository

The repository contract loads, saves and invalidates a security context by using bounded, redacted request metadata.
Persistence is explicit after successful authentication or an approved context transition.
Merely reading an existing context does not rewrite the session automatically.

Applications own durable session records, expiry, revocation, device policy and database transactions.
Butter owns when repository operations occur relative to authentication, authorization and response commitment.
The response-extension `SessionTransition` lets a route that authenticates a request body request establishment, refresh, CSRF re-exposure or logout without giving the route direct cookie-writing authority.

## Session authentication strategy

Successful login and privilege elevation invoke a session strategy before the new context is persisted.
Every stateful plan requires an application-supplied strategy, and Butter rejects an identifier that did not rotate.
Additional strategies may enforce concurrent-session or assurance policy through application callbacks.

Cancellation or an unconfirmed persistence result must not be reported as a successful login.
The response must not expose a new session identifier until the required persistence contract succeeds.
If persistence succeeds but response construction or delivery fails, server state may exist even though the client did not receive the new identifier.
Butter does not automatically replay an unconfirmed write or claim that dropping a future reversed remote work.

## Cookies

Butter reuses the upstream `BrowserCookie` transport instead of maintaining another cookie parser or serializer.
It fixes browser credentials to host-only scope and root path, requires an explicit name, `SameSite`, visibility and lifetime, and derives `Secure` from an explicit HTTPS or loopback-development origin.
HTTPS policy requires a case-sensitive `__Host-` cookie name, while plain HTTP is accepted only for explicit loopback origins.
`SessionCookie` additionally rejects any authentication cookie that is not `HttpOnly`.
Cookie values are credentials and are always redacted.

Domain-wide and non-root-path authentication cookies are not exposed by this slice because they expand the compromise boundary.
Logout expires the browser cookie and invokes repository invalidation, while documenting that response loss can leave the client uncertain.

## CSRF decision

Any chain that authenticates through automatically attached browser credentials must make an explicit CSRF decision.
The standard helper selects every method except `GET`, `HEAD`, `OPTIONS` and `TRACE`, but the stateful builder still requires the application to install it explicitly.
A bearer-only chain may explicitly select stateless CSRF behavior when browsers do not attach its credentials automatically.

The builder rejects cookie authentication combined with an omitted CSRF policy.
Disabling CSRF requires a visible configuration call and a documented rationale in consuming applications.

## CSRF components

The web package defines separate extension contracts for:

- A token repository that creates, loads, rotates and invalidates expected tokens.
- A request handler that exposes and resolves presented tokens.
- A matcher that decides whether the request requires protection.
- A denial handler for missing or invalid tokens.

Token comparison is constant time after strict length bounds.
CSRF tokens are application-generated random bearer values and are redacted from diagnostics.
They are created after login, rotate with session refresh or elevation, and are invalidated and expired during logout.
Butter emits neither the session cookie nor the CSRF cookie unless all required repository operations report success.
Failure after one durable operation may leave inaccessible server state, so adapters must document transaction and reconciliation behavior rather than infer rollback.

## Origin validation

Unsafe browser requests also receive origin validation against an application allow-list.
The policy prefers `Origin` and uses `Referer` only under a documented fallback rule.
The implemented policy never derives trust from forwarding headers.

Origin validation supplements rather than silently replaces token validation for stateful browser applications.

## Single-page applications

The initial design must support an Angular-compatible cookie and header flow without embedding Angular-specific behavior into core.
The application can choose conventional `XSRF-TOKEN` and `X-XSRF-TOKEN` names.
Secure deployments configure a `__Host-` CSRF cookie name in both Butter and the SPA client.
If JavaScript must read the CSRF cookie, only that CSRF token cookie may omit `HttpOnly`; the authentication cookie remains `HttpOnly`.

`SessionTransition::expose_csrf` lets an authenticated safe-method endpoint re-expose an existing token after application startup without rewriting session state or creating a token.
Login and refresh responses expose newly created or rotated tokens only after persistence.
Logout expires both cookies after invalidation.
If the repository has no token for an existing session, re-exposure fails closed instead of creating persistence as a side effect of a safe request.

## Deferred features

BREACH-masked token representations, request caching, remember-me authentication and concurrent-session limits require separate reviewed milestones.
Their future addition must preserve the same repository, handler and strategy seams rather than changing application identity contracts.
