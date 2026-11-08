# Butter Actuator planning index

## Status

This is the accepted design record for Butter Actuator.
The generic core and explicitly attached Boot HTTP integration are now implemented together; see [current usage](../../actuator.md).
The remaining consumer-validation phase is not established by this framework implementation, and the API remains experimental and unpublished.
The documents below retain the original design language and acceptance requirements, not evidence of downstream runtime acceptance.

## Objective

Butter Actuator should provide transport-independent operational endpoint definitions and health aggregation inspired by Spring Boot Actuator.
It should preserve Butter's explicit Rust ownership, protected startup and checked shutdown model rather than copying Java annotations, runtime classpath discovery or dependency injection.
The framework should own generic endpoint and health mechanisms while consuming applications decide which real dependencies affect readiness.

## Accepted direction

- Add one transport-independent `butter-actuator` package.
- Do not add a `butter-actuator-web` package.
- Keep `butter-web` independent of Actuator.
- Keep `butter-boot` dependent on `butter-web` and add an optional `butter-actuator` dependency behind a Boot feature.
- Let Boot map typed Actuator operations onto protected HTTP routes only when an application explicitly attaches an Actuator.
- Use explicit Rust builders and typed operations instead of annotations, reflection or global registration.
- Expose `GET /actuator/health`, `GET /actuator/health/liveness` and `GET /actuator/health/readiness` in the first web slice.
- Remove the framework-provided `/live` and `/ready` routes without aliases.
- Keep liveness independent of external systems.
- Let applications explicitly place dependency contributors in readiness.
- Build continuous, bounded and supervised dependency sampling on Butter core's existing health monitor rather than running probes in request handlers.
- Return sanitized endpoint results while retaining concrete failures only for deliberate in-process diagnostics.
- Change the `butter` facade to an empty default feature set.
- Keep `web`, `data`, `workflow` and `actuator` optional, with `workflow` continuing to imply `data`.

## Documents

- [Architecture](architecture.md)
- [Endpoint and web exposure](endpoints-and-web.md)
- [Health model](health.md)
- [Feature model and compatibility](feature-model.md)
- [Testing](testing.md)
- [Delivery roadmap](delivery-roadmap.md)

## Initial non-goals

The first slice does not include metrics, environment or configuration inspection, log-level mutation, thread dumps, request history, audit events, arbitrary administrative commands or shutdown endpoints.
It does not add a separate management listener, JMX adapter, authentication mechanism, database-specific health contributor or infrastructure provisioner.
It does not stabilize arbitrary third-party endpoint registration before a second endpoint or transport demonstrates the required generic shape.
It does not make a successful health response proof that a later request, dependency operation or external effect will succeed.

## Spring Boot references

- Actuator overview: <https://docs.spring.io/spring-boot/reference/actuator/index.html>
- Enabling Actuator: <https://docs.spring.io/spring-boot/reference/actuator/enabling.html>
- Endpoints, health contributors and probes: <https://docs.spring.io/spring-boot/reference/actuator/endpoints.html>
- HTTP monitoring exposure: <https://docs.spring.io/spring-boot/reference/actuator/monitoring.html>

The references were reviewed on 2026-11-08.
They inform component separation and endpoint conventions, but Butter's public contracts remain Rust-specific.

## Implementation decisions

- The deterministic catalog covers only the three built-in health views, without arbitrary endpoint registration.
- Contributor registration returns a typed local diagnostics handle retaining the last concrete failure separately from sanitized monitor snapshots.
- Repeated Boot attachment returns a construction error.

No public API should be stabilized until the feature-isolation matrix and a real downstream integration have exercised the complete startup, health-change and shutdown path.
