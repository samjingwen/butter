# Butter Actuator architecture

## Design principle

Actuator defines operational endpoints and their typed results independently of any transport.
Web provides generic protected HTTP composition independently of Actuator.
Boot performs the optional composition when an HTTP application explicitly supplies an Actuator.

This follows Spring Boot's separation between Actuator endpoint operations and web exposure without copying annotations, bean discovery or runtime reflection.

## Proposed package

### `butter-actuator`

`butter-actuator` owns validated endpoint and contributor identities, operation metadata, health groups, contributor registration, aggregation, sanitized results and the supervised sampling definitions required by those contributors.
It depends on `butter-core` for lifecycle observation, health monitoring, deadlines, cancellation, supervision and protected registration.
It does not depend on Axum, `butter-web`, `butter-boot`, SQLx, a database driver or an application schema.

The first public endpoint is health.
The package may use an internal operation catalog so transports can discover built-in operations, but the first release does not promise an arbitrary type-erased custom endpoint API.

### `butter-web`

`butter-web` remains generic HTTP infrastructure.
It owns route inventory, conflict checking, request admission, response-construction deadlines, native Axum interoperability and protected probe mounting mechanisms.
It does not depend on `butter-actuator` and does not assign Actuator meaning to any route by itself.

### `butter-boot`

`butter-boot` continues to depend on `butter-core` and `butter-web` because its current responsibility is HTTP application bootstrap.
An `actuator` feature adds an optional dependency on `butter-actuator` and the adapter that maps Actuator operations into the protected HTTP boundary.
Boot owns route placement, HTTP method and status mapping, JSON serialization, response headers and route-conflict refusal.
Boot does not own health aggregation or dependency probing.

There is no `butter-actuator-web` package.
The composition is small, specific to the existing Boot bootstrap and not yet a reusable transport component with an independent lifecycle.

## Dependency direction

```text
butter-core
    ^
    |
butter-actuator       butter-web
          ^              ^
           \            /
            butter-boot
```

The Boot-to-Actuator edge exists only when Boot's `actuator` feature is selected.
Core and web remain independent of Actuator.
Actuator remains usable in a non-web process for direct typed observation even though the first transport integration is HTTP.

## Explicit composition

Selecting Cargo features makes APIs available but must not silently change a running application's routes.
Cargo feature unification can enable a feature because of another dependency, so route exposure based only on compile-time feature presence would be unsafe and surprising.

An HTTP application explicitly attaches an inert Actuator before startup:

```rust,ignore
let actuator = Actuator::builder()
    .readiness_probe(store_id, health_policy, || async {
        check_primary_store().await
    })?
    .build()?;

let running = Application::new(routes)
    .actuator(actuator)
    .start()
    .await?;
```

`Actuator::builder`, contributor registration and `build` perform validation and allocation only.
They perform no probe I/O, bind no listener and create no detached task.
`Application::actuator` is available only when Boot is compiled with its Actuator feature.
Calling it more than once is a construction error or is prevented by a consuming API.

Actuator also exposes a transport-independent registration operation that accepts Butter core's protected registration target and lifecycle observer.
Boot invokes that operation during its protected startup and receives the running typed endpoint view used by the web adapter.
A non-web process invokes the same operation inside its own protected startup before it can observe live endpoint state.
An Actuator plan that is built but never registered remains inert, owns no writer and cannot claim that a dependency is healthy.

## Startup ownership

Protected startup validates the complete Actuator plan and application route inventory before listener binding.
It registers every continuous health monitor as an ordinary supervised component and obtains read-only health views before assembling the HTTP boundary.
Monitor registration failure, duplicate contributor names or route conflicts fail startup before the listener is bound.

A monitor acknowledges component startup when its writer is running, not when its first dependency probe succeeds.
The application can therefore start while a dependency remains unavailable, and readiness stays unavailable until a fresh successful observation exists.
Applications that require a dependency or schema before binding must perform that separate bounded startup validation outside Actuator.

Probe failure and timeout update contributor state without terminating the process.
An unexpected monitor stop invalidates its reader and makes every group containing it unhealthy.
A supervised fatal component failure can independently cause the ordinary Butter shutdown path.

## Read path

Endpoint reads are point-in-time observations of already published in-memory state.
They perform no network, filesystem or database I/O, start no task, refresh no timestamp and wait for no probe.
They read contributors in deterministic registration order and calculate a fresh group result for each invocation.
The result can become obsolete immediately and is not a readiness lease.

The web adapter invokes the same typed health operation that a non-web caller can invoke directly.
HTTP-specific status codes and serialization do not enter the Actuator domain model.

## Shutdown ownership

Actuator monitors observe the existing supervisor's drain and cancellation signals.
They stop probing during drain, destroy active probe futures according to Butter core's cancellation contract and invalidate their readers when their writers end.
They do not create a second supervisor or extend process ownership outside `RunningApplication`.

Readiness changes to unavailable as soon as lifecycle drain is observed.
Liveness remains independent of external contributors while the process and HTTP connector are still serving.
Listener closure and checked completion remain Boot responsibilities.

## Error and disclosure boundary

Contributor failures remain concrete in process so trusted application diagnostics can inspect their error chain deliberately.
Standard endpoint results, `Debug` output, metrics labels and ordinary status events must not format or serialize those errors.
The HTTP adapter receives only sanitized status results and never receives a credential, SQL text, remote address, driver message or application error string.

The exact local diagnostics handle is an implementation design question, but it must be capability-based and unavailable from unauthenticated HTTP endpoint input.
Butter installs no global tracing subscriber and does not assume that arbitrary application errors are safe to record.

## Deliberate differences from Spring Boot Actuator

- Butter uses explicit builders and ownership instead of endpoint annotations and bean discovery.
- Butter does not expose an endpoint merely because a Cargo feature was unified into the build.
- Butter's initial endpoint set contains health only.
- Butter's initial web integration uses the main application listener rather than a separate management context.
- Butter never adds external dependencies to liveness.
- Butter does not auto-discover database, cache, broker or filesystem contributors.
- Butter does not provide broad configuration properties that can expose sensitive management data accidentally.
