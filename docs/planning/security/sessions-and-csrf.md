# Sessions and CSRF

## Stateful and stateless security

Each security chain declares whether it loads and persists authentication context.
A stateless chain uses no context repository and authenticates every protected request from presented credentials.
A stateful chain uses an application-supplied context repository and a browser-safe session identifier.

Butter does not supply a hidden in-memory production session store.
An in-memory implementation may exist only as an explicitly test-oriented utility.

## Security context repository

The repository contract loads, saves and invalidates a security context by using bounded, redacted request metadata.
Persistence is explicit after successful authentication or an approved context transition.
Merely reading an existing context does not rewrite the session automatically.

Applications own durable session records, expiry, revocation, device policy and database transactions.
Butter owns when repository operations occur relative to authentication, authorization and response commitment.

## Session authentication strategy

Successful login and privilege elevation invoke a session strategy before the new context is persisted.
The default stateful strategy requires session identifier rotation to resist fixation.
Additional strategies may enforce concurrent-session or assurance policy through application callbacks.

Cancellation or an unconfirmed persistence result must not be reported as a successful login.
The response must not expose a new session identifier until the required persistence contract succeeds.

## Cookies

Cookie policy requires explicit name, path, `Secure`, `HttpOnly` and `SameSite` choices.
Production builders reject browser session cookies that omit `Secure` unless an explicit local-development mode is selected.
Cookie values are credentials and are always redacted.

Domain-wide cookies require an explicit decision because they expand the compromise boundary.
Logout expires the browser cookie and invokes repository invalidation, while documenting that response loss can leave the client uncertain.

## CSRF decision

Any chain that authenticates through automatically attached browser credentials must make an explicit CSRF decision.
The safe default enables protection for unsafe HTTP methods.
A bearer-only chain may explicitly select stateless CSRF behavior when browsers do not attach its credentials automatically.

The builder rejects cookie authentication combined with an omitted CSRF policy.
Disabling CSRF requires a visible configuration call and a documented rationale in consuming applications.

## CSRF components

The web package should define extension contracts equivalent in responsibility to:

- A token repository that creates, loads, rotates and invalidates expected tokens.
- A request handler that exposes and resolves presented tokens.
- A matcher that decides whether the request requires protection.
- A denial handler for missing or invalid tokens.

Token comparison is constant time after strict length bounds.
CSRF tokens are random bearer values, are redacted from diagnostics and rotate after login and logout.

## Origin validation

Unsafe browser requests also receive origin validation against an application allow-list.
The policy prefers `Origin` and uses `Referer` only under a documented fallback rule.
Forwarded scheme and host values are accepted only from configured trusted proxies.

Origin validation supplements rather than silently replaces token validation for stateful browser applications.

## Single-page applications

The initial design must support an Angular-compatible cookie and header flow without embedding Angular-specific behavior into core.
The application can choose conventional `XSRF-TOKEN` and `X-XSRF-TOKEN` names.
If JavaScript must read the CSRF cookie, only that CSRF token cookie may omit `HttpOnly`; the authentication cookie remains `HttpOnly`.

The client needs an explicit way to obtain a fresh token after application startup, login and logout.
The framework should support deferred token loading so safe requests do not require session persistence solely for CSRF.

## Deferred features

BREACH-masked token representations, request caching, remember-me authentication and concurrent-session limits require separate reviewed milestones.
Their future addition must preserve the same repository, handler and strategy seams rather than changing application identity contracts.
