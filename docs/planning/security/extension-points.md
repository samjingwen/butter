# Extension points

## Extension philosophy

Butter should expose narrow contracts for real responsibilities rather than one universal plugin interface.
Framework-owned ordering protects invariants while application-owned implementations supply identity and business policy.

The first implementation should prototype both generic and object-safe boundaries before stabilizing public traits.
Object erasure is justified only where heterogeneous runtime composition requires it.
Static typing remains preferred inside a concrete provider or policy.

## Planned contracts

| Contract | Responsibility |
| --- | --- |
| `AuthenticationManager` | Authenticate one request through a configured strategy. |
| `AuthenticationProvider` | Recognize and verify one credential family. |
| `Principal` | Expose stable, non-secret caller identity. |
| `SecurityContextRepository` | Load, save and invalidate request authentication context. |
| `SessionAuthenticationStrategy` | Apply fixation and elevation policy before persistence. |
| `AuthorizationManager<C>` | Decide access to a typed protected context. |
| `RequestMatcher` | Select a security chain or request policy without side effects. |
| `CredentialExtractor` | Parse one bounded credential representation from HTTP. |
| `AuthenticationEntryPoint` | Request credentials or return an unauthenticated response. |
| `AccessDeniedHandler` | Return the authenticated-but-denied response. |
| `CsrfTokenRepository` | Create, load, rotate and invalidate CSRF tokens. |
| `SecurityEventSink` | Receive bounded, credential-free security events. |

Names may change after prototype review, but responsibilities should remain separate.

## Pipeline extensions

Applications may add Tower layers or Butter security stages before or after named semantic anchors.
Each extension declares a unique identifier, required predecessor state and whether it can terminate a request.
The builder validates dependency and ordering constraints.

Applications cannot replace mandatory context cleanup, request-integrity checks or exception translation.
An extension requiring authenticated identity cannot be placed before authentication.

## Optional adapters

Optional packages can adapt proven libraries without pulling their dependency graph into every application.
Potential adapters include password hashing, JWT resource-server verification, SQLx session persistence and OAuth client support.

An adapter must have a real consumer, a stable upstream dependency and contract tests before it becomes a workspace package.
The base security feature does not depend on JOSE, password-hashing, database or OAuth libraries.

JWT issuance, OAuth authorization-server endpoints and identity-provider storage are outside Butter's scope.

## Configuration

Configuration uses inert Rust builders with explicit dependencies.
There is no classpath scanning, reflection, global registry or automatic provider discovery.
The application constructs providers, managers, repositories and handlers directly.

Defaults apply only where the framework can prove they are safe.
Missing application policy is a build error or deny decision rather than an inferred allow.

## Compatibility

Butter Security remains experimental until at least one real consumer exercises stateful and stateless chains.
Public trait changes follow the workspace version and release policy once publication is authorized.
Until then, consuming repositories pin an immutable reviewed Git revision rather than a moving branch.

Feature combinations receive compile checks so an HTTP-only application does not inherit database, JWT or workflow dependencies.
The minimal facade remains independent of every security package when the security feature is disabled.

## Documentation contract

Every public extension trait requires:

- A responsibility statement.
- Success, rejection and operational-failure semantics.
- Cancellation behavior.
- Secret-handling guarantees.
- Object-safety or generic-use guidance.
- At least one synthetic implementation example.
- A reusable conformance test where behavior can be standardized.
