# Authentication

## Responsibilities

Authentication turns presented credentials into a credential-free statement about the caller.
Butter owns generic orchestration and consuming applications own credential meaning, identity lookup and acceptance policy.

## Authentication request

An authentication request represents credentials presented for verification.
Examples include a session cookie, bearer token, API key, username and password, client certificate or passkey assertion.

Credential-bearing values must redact themselves from `Debug`, display and error output.
They should avoid cloning, use bounded inputs and zeroize memory when the underlying representation supports it.
They must never enter traces, metrics labels, security events or the resulting security context.

The core uses an object-safe authentication-request trait with typed `Any` downcasting at a recognizing provider.
The supplied generic credential request owns zeroizing, redacted credential material and is neither clonable nor displayable.
Provider and manager traits return boxed borrowing futures so ordered heterogeneous composition does not clone or serialize credentials.
Applications may define typed requests without converting every mechanism into an untyped string map.

## Authenticated result

Successful authentication produces an immutable result containing:

- A principal with a stable subject identifier.
- A display or diagnostic name that is not an authorization key.
- Validated authorities.
- The successful authentication mechanism.
- Authentication time.
- Assurance or completed-factor information.
- Non-secret details explicitly approved for policy evaluation.

The result never contains the original credential.
Applications may wrap domain-specific principal data behind a typed or safely downcastable contract, but Butter must not require a universal user schema.

## Authorities

An authority is a validated application-wide permission such as a role or scope.
Authority comparison is exact and case-sensitive unless the application explicitly constructs a different policy.
Butter does not apply an implicit role prefix.

Authorities should remain coarse.
Object-specific permission checks belong in authorization managers that receive the protected resource context.

## Authentication manager

The authentication manager is the stable entry point used by web mechanisms and application code.
It delegates to an ordered provider set and returns either an authenticated result or a typed failure.

The standard provider manager supports provider composition without exposing provider implementation details to callers.
An optional parent or fallback manager may be considered only after a demonstrated multi-chain need.

## Authentication provider

Each provider recognizes and verifies one credential family.
A provider returns one of three outcomes:

- `Authenticated` when it recognizes and accepts the request.
- `Unsupported` when the request belongs to another mechanism and the next provider may evaluate it.
- `Rejected` when it recognizes the request but cannot authenticate it.

`Rejected` is terminal.
Continuing after a recognized credential is rejected could let a weaker provider bypass a stronger provider's decision.
If every provider returns `Unsupported`, the manager returns a typed unsupported-mechanism failure.

Provider timeouts, cancellation and unavailable dependencies are operational failures rather than invalid-credential results.
The framework must preserve that distinction internally while allowing neutral external responses.

## Credential extraction

Web credential extractors translate request material into authentication requests.
Extraction is separate from verification so custom transports can reuse providers and custom providers can reuse extractors.

The initial web package supplies an extractor contract and a strict bounded bearer adapter.
Applications can implement API-key and other header adapters through the same contract.
Cookie credentials remain part of the stateful browser-security phase.

The planned mechanism set includes:

- `Authorization` bearer credentials.
- Cookie credentials.
- API key headers.
- Explicit request-body login endpoints implemented by applications.

Multiple simultaneous credential sources are rejected by the implemented web spine.
No weaker collision policy is exposed by the initial builder.

## Existing context and reauthentication

A context repository may load an already authenticated context before proactive credentials are processed.
The configured chain decides whether new credentials replace, strengthen or conflict with existing authentication.
Privilege elevation and additional-factor completion must create a new context rather than mutating one shared across requests.

The result model must be extensible enough for multi-factor and step-up authentication without implementing passkeys, one-time tokens or provider-specific protocols in core.

## Success and failure handling

Authentication success handlers may save context, rotate a session, return an API response or redirect a browser.
Authentication failure handlers map typed internal failures to neutral client responses.
Handlers receive redacted reason codes and must not receive raw credentials unless they are the component that verifies them.

## Events

Butter may emit typed authentication success, rejection and operational-failure events through an application-supplied event sink.
The sink is not a durable audit log and does not replace application transactions.
The event model excludes credentials and bounds application-supplied details.
