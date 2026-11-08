# Butter Actuator health model

## Health views

The health endpoint exposes three purpose-specific views rather than treating every check as interchangeable.

### Overall health

Overall health combines lifecycle availability with every registered health contributor.
It is `UP` only when lifecycle state permits service and every included contributor has a fresh successful observation.
It is intended for human and monitoring-system summaries, not automatic restart policy.

### Liveness

Liveness reports whether the process is still capable of serving the small in-process probe while the connector is available.
It never includes a database, broker, cache, remote API or other external dependency.
External failure must not cause orchestrators to restart every otherwise functioning instance and amplify a shared outage.

Starting and ordinary graceful drain do not become external-dependency liveness failures.
Once the listener is closed, the route is unreachable regardless of the last computed liveness value.
The first slice does not add a mutable application API that can declare an otherwise running process irrecoverably broken.

### Readiness

Readiness combines Butter lifecycle readiness with contributors that the application explicitly places in the readiness group.
Starting, draining and stopped lifecycle states are not ready.
Every selected dependency must have a fresh successful observation for readiness to be `UP`.

The application decides whether losing a dependency should remove one instance from service.
Butter does not add every overall health contributor to readiness automatically.
No external contributor can be added to liveness in the first slice.

## Contributor registration

Each contributor has one validated identity and one explicit group policy.
Names are unique within an Actuator and use the same bounded safe-name principles as Butter component names.
Duplicate or invalid names fail inert construction before startup.

The initial group choices are:

- Overall only.
- Overall and readiness.

Every contributor participates in overall health.
Readiness participation requires the second choice.
Lifecycle state is built in and is not replaceable by an application contributor.

Registration order is retained for deterministic diagnostics and tests.
Aggregation is logically order-independent because one unhealthy required contributor makes the group unhealthy.

## Continuous sampling

Asynchronous dependency probes run through Butter core's `HealthMonitor` under supervisor ownership.
Each probe definition supplies a validated `HealthPolicy` covering total probe budget, delay between completed attempts, maximum observation age and scheduling margin.
The entire probe future, including resource acquisition, is inside the timeout and cancellation boundary.

Probes run sequentially per contributor.
A slow attempt does not queue overlapping attempts or catch-up work.
Endpoint requests never invoke a probe and cannot increase dependency load.

The Actuator integration uses the core health state without weakening it:

| Core contributor state | Group contribution |
| --- | --- |
| `Healthy` | `UP` |
| `Unknown` | `DOWN` |
| `Failed` | `DOWN` |
| `TimedOut` | `DOWN` |
| `Stale` | `DOWN` |
| `Stopped` | `DOWN` |

No completed probe means `Unknown`, so readiness remains unavailable until each required contributor has succeeded.
A prior success expires when it reaches maximum age even if no newer failure was published.
Dropping or ending the sole writer changes the state to `Stopped` even when its last observation succeeded.

## Aggregation

The first status vocabulary is the minimal `UP` and `DOWN` pair.
All required observations must be `UP`; otherwise the aggregate is `DOWN`.
There is no majority, quorum, fallback or last-known-good override in framework policy.

Overall health reads all contributors plus lifecycle.
Readiness reads lifecycle readiness and only contributors explicitly selected for readiness.
Liveness reads lifecycle and connector-local state without reading dependency contributors.

The lifecycle mapping is explicit:

| Lifecycle state | Overall | Liveness | Readiness |
| --- | --- | --- | --- |
| `Starting` | `DOWN` | `UP` while observable | `DOWN` |
| `Ready` | Contributor aggregate | `UP` | Readiness contributor aggregate |
| `Draining` | `DOWN` | `UP` while observable | `DOWN` |
| `Stopped` | `DOWN` | `DOWN` in process and unreachable over HTTP | `DOWN` |

An empty contributor set has an `UP` aggregate.
The lifecycle row still controls the final result, so only `Ready` can produce `UP` overall or readiness.

Aggregation samples published state one contributor at a time and then performs a final lifecycle read so a drain observed during evaluation overrides earlier healthy observations.
The operation is a bounded in-memory snapshot, not a transaction across independent monitors.
The result can race with the next state transition and provides no lease.

## Failure retention

The concrete error from the latest failed probe may be retained in process for deliberate trusted diagnostics.
Actuator endpoint results collapse that failure to `DOWN`.
Timeout, staleness and writer stop also have sanitized in-process categories that do not contain application error text.

Ordinary `Debug` implementations must redact concrete error values.
No endpoint response includes an error chain, query, credential, connection string, remote address or stack trace.
The framework does not log concrete failures automatically because an application's error type may contain sensitive data.

## Policy boundaries

A successful probe means only that its application-supplied future returned success within the configured budget recently enough.
It is not proof of transaction commit, schema compatibility, authorization, future capacity or exactly-once external effects.
Cancellation drops the probe future but does not prove cancellation of remote work or detached tasks created by application code.
Probe design, credentials and the decision to include a dependency in readiness remain application policy.
