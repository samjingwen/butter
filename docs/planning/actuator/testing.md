# Butter Actuator testing

## Verification strategy

The Actuator implementation requires unit, feature-isolation, supervised-runtime and real loopback HTTP acceptance.
Synthetic probes are sufficient for the framework because database-specific behavior belongs to consuming applications.
The ordinary `bash scripts/check.sh` gate must include the new crate, feature combinations, doctests, rustdoc and process smoke behavior.

## Actuator unit contracts

Unit tests must cover:

- Valid, invalid and duplicate endpoint and contributor identities.
- Inert builder construction with no probe invocation.
- Deterministic operation discovery and contributor ordering.
- Overall-only and readiness group membership.
- Aggregation of every contributor state.
- Lifecycle precedence over earlier healthy snapshots.
- Initial unknown state before the first completed probe.
- Transition through success, failure, timeout, staleness and writer stop.
- Sequential polling without overlapping or queued catch-up attempts.
- Drain and cancellation while a probe is pending.
- Concrete failure retention for local diagnostics and redaction from ordinary `Debug` and endpoint results.
- Rejection of any attempt to add an external contributor to liveness.

Time-sensitive tests should use controlled Tokio time where the production mechanism permits it.
Tests must not depend on arbitrary sleeps when a notification or paused clock can establish the transition deterministically.

## Feature graph contracts

The source-graph gate must execute Cargo's resolved graphs and compile representative combinations.
It must prove:

- `butter` with no features does not include web, Boot, Actuator, SQLx or workflow.
- `actuator` alone does not include Axum, `butter-web` or `butter-boot`.
- `web` alone does not include `butter-actuator`, SQLx or workflow.
- `data` alone does not include web, Actuator or workflow.
- `workflow` includes data and does not include web or Actuator.
- `web,actuator` enables Boot's adapter.
- `web,data,actuator` does not enable workflow.

The runnable hello example must declare every feature it requires explicitly after facade defaults become empty.

## Boot loopback contracts

Real TCP tests must cover:

- No Actuator routes when no Actuator is attached.
- Healthy JSON and status 200 on all three routes for a healthy plan.
- Status 503 and sanitized JSON for unavailable overall and readiness views.
- Liveness remaining healthy during a synthetic external dependency outage.
- Readiness becoming healthy only after every required contributor has a fresh success.
- Readiness becoming unavailable on failure, timeout, staleness, monitor stop and lifecycle drain.
- Overall-only contributor failure changing overall health without changing readiness.
- Content type and `Cache-Control: no-store` response headers.
- `HEAD` returning the `GET` status and headers without a body.
- Methods other than `GET` and `HEAD` returning method not allowed.
- Query input not enabling details or invoking probes.
- Exact and wildcard application route conflicts under `/actuator` failing before bind.
- `/live` and `/ready` returning 404 in the migrated default application.
- Probe requests remaining bounded in-memory reads during a blocked dependency probe.
- Checked shutdown releasing the listener and settling monitor components.

The tests must assert that response bodies do not contain synthetic secret markers from contributor failures.
At least one test should retain a local diagnostic cause while proving the corresponding HTTP response contains only `DOWN`.

## Compatibility acceptance

Repository documentation, examples and smoke scripts must contain no active use of framework `/live` or `/ready` routes after implementation.
Historical planning statements may name them only when clearly describing the removed contract.
The complete base-to-head diff must show no `butter-actuator-web` package or hidden web dependency from Actuator.

## Evidence boundaries

Passing framework tests proves generic lifecycle, aggregation and HTTP mapping behavior against synthetic contributors.
It does not prove a downstream application's database query, credentials, schema compatibility, deployment health-check configuration or network policy.
Each consumer must test its own contributor and operational migration against owned disposable infrastructure.
