# Actuator

Butter Actuator is experimental transport-independent operational health, with optional HTTP integration in Boot.
It is not a database checker, identity system, infrastructure provisioner or general administrative API.

## Select and attach

Facade defaults are empty.
Select `web` for HTTP, `actuator` for health, or both for the optional Boot integration:

```toml
butter = { git = "https://github.com/samjingwen/butter", rev = "<reviewed-commit>", features = ["web", "actuator"] }
```

Explicit attachment is required even when Cargo feature unification enables the adapter:

```rust,no_run
use butter::{Application, actuator::Actuator, web::Router};
# async fn example() -> Result<(), butter::core::BoxError> {
let running = Application::new(Router::new())
    .actuator(Actuator::builder().build())?
    .start().await?;
running.shutdown().await?;
# Ok(()) }
```

Attachment is fallible to reject a second plan rather than silently replacing the first.
Without attachment, Boot neither serves Actuator routes nor reserves `/actuator`.
With attachment, exact, nested, captured, wildcard and declared routes that overlap any part of that subtree fail assembly before listener binding.

## Contributors

```rust,no_run
use butter::actuator::{Actuator, ContributorGroup, ContributorId};
use butter::core::health::HealthPolicy;
use std::{convert::Infallible, time::Duration};
# fn example() -> Result<(), butter::core::BoxError> {
let second = Duration::from_secs(1);
let policy = HealthPolicy::new(second, second, second * 3, second)?;
let mut builder = Actuator::builder();
let diagnostics = builder.probe(
    ContributorId::new("dependency.health")?,
    ContributorGroup::Readiness,
    policy,
    || async {
        // Supply a bounded application-owned probe, including acquisition here.
        Ok::<_, Infallible>(())
    },
)?;
let plan = builder.build();
# let _ = (plan, diagnostics);
# Ok(()) }
```

Construction performs validation and allocation only, with no probes or spawned tasks.
At most 64 contributors are permitted, with unique safe static identities of 1-96 ASCII alphanumeric, dot, underscore or hyphen bytes.
Their identities also name supervised components and must not collide with other registered components such as Boot's `http` or optional `signals` component.
`Overall` membership affects only overall health; `Readiness` affects both overall health and readiness.
External liveness membership is unrepresentable.
No contributor is discovered automatically from `data` or another dependency.

Protected registration transfers each core `HealthMonitor` into the existing supervisor and returns `RunningActuator` for typed reads.
A non-web process can call `plan.register_in(scope, lifecycle)` during its own protected startup, then call `running.health(HealthView::Readiness)` without selecting a web dependency.
Retained diagnostics do not keep a monitor writer alive.
Partial registration errors require the enclosing protected startup to settle already registered components.

Probes execute sequentially under the core policy's total timeout, completion-to-next delay, maximum observation age and scheduling margin.
Startup acknowledgement means the monitor is running, not that a dependency has succeeded.
Factories, polls and destructors must not block, and application probes must not detach work.
If an application requires dependency/schema validation before binding, it must perform that separate startup check.

## Operations and HTTP

`HEALTH_OPERATIONS` deterministically lists overall, liveness and readiness reads for the `health` endpoint.
There is no arbitrary custom endpoint registration API.
Only the typed aggregate status leaves the Actuator boundary; Boot owns paths, methods, headers and serialization.

| GET and HEAD path | Meaning |
| --- | --- |
| `/actuator/health` | Lifecycle readiness and every contributor. |
| `/actuator/health/liveness` | Process lifecycle only, independent of dependencies. |
| `/actuator/health/readiness` | Lifecycle readiness and explicitly selected readiness contributors. |

GET returns exactly `{"status":"UP"}` with 200 or `{"status":"DOWN"}` with 503, with `Content-Type: application/json` and `Cache-Control: no-store`.
HEAD evaluates the same operation with the same status and headers and no body.
Other methods get the HTTP stack's normal 405 response.
Query input neither enables details nor invokes a probe.
The endpoint includes no contributor names, causes, timestamps, durations or configuration.

| Lifecycle | Overall | Liveness | Readiness |
| --- | --- | --- | --- |
| Starting | DOWN | UP while observable | DOWN |
| Ready | All contributors | UP | Selected contributors |
| Draining | DOWN | UP while observable | DOWN |
| Stopped | DOWN | DOWN | DOWN |

An empty contributor aggregate is UP.
Only a fresh core `Healthy` observation contributes UP; `Unknown`, `Failed`, `TimedOut`, `Stale` and `Stopped` contribute DOWN.
Reads sample contributors in registration order, then read lifecycle last.
They perform bounded in-memory reads only, with no I/O, tasks, refreshes or probe waits.
Snapshots are not transactions across monitors or leases: they can become obsolete immediately and prove nothing about the next operation, commit, schema compatibility or external effect.

## Diagnostics and shutdown

`ContributorDiagnostics<E>::last_failure()` deliberately clones the last concrete failure for trusted inspection, even after recovery, timeout or stop.
This historical failure is read separately from `snapshot()` and need not explain its current status.
Ordinary diagnostics `Debug` and endpoint results redact failures; Butter does not automatically log arbitrary application errors.
Endpoint readers hold only sanitized core state, so dropping a read snapshot cannot run an application error destructor.

Drain stops sampling, destroys active probe futures and invalidates stopped writers while ordinary Boot shutdown settles the listener and registered monitors.
Dropping a future does not prove cancellation of remote work or detached tasks created by application code.
A closed listener cannot report its final state over HTTP, regardless of the last in-process result.
Successful health does not establish later request admission or completion.
Health endpoints use the main listener and supply no authentication or network access policy.

## Migration and evidence

The facade's former default `web` feature is removed; HTTP consumers must now select it explicitly.
The former framework `/live` and `/ready` routes are removed without aliases or reservation.
Without an application route there, they return 404; any application-owned replacement is ordinary guarded traffic, not a framework health probe.
Migrate operational checks with the reviewed Butter revision, without mixing component revisions.

Run `bash scripts/check.sh` for the generic feature, lifecycle and loopback contracts and `bash scripts/check-workflow.sh` for owned disposable PostgreSQL persistence acceptance.
Synthetic framework tests do not qualify a real consumer's probes, credentials, schema, deployment checks or network policy.
Consumer validation, dependency-pin updates and publication are separate actions, not performed by this implementation.
