# Architecture

## Design principle

Reuse mechanisms, keep business policy explicit, and let the library own sequencing that must always be correct.
Spring Boot inspires the coherent startup experience, not Java reflection or inheritance patterns.
Introduce abstractions for actual responsibilities and invariants, not to give every dependency another generic interface.

## Dependency direction

The application consumes the `butter` facade or a specific component.
`butter-boot` composes core and web, while core never depends on security, Actuator, web, data or workflow.
`butter-security` is transport-independent and owns credential-safe provider orchestration, immutable contexts and fail-closed authorization contracts without depending on core, web or persistence.
`butter-actuator` depends only on core and owns health operations, aggregation and contributor plans.
Boot's optional `actuator` feature provides HTTP mapping; `butter-web` remains independent of Actuator.
The facade has empty defaults and forwards `actuator` to Boot only when `web` has already selected Boot.
`butter-data` exposes owned PostgreSQL operations and native SQLx without inventing an ORM or universal repository.
`butter-workflow` directly owns the adopted persistence implementation and its completion extension; its durable model types remain a pinned upstream dependency.
There is one resolved SQLx graph, so data scopes and workflow operations use the same types.

## Bootstrap ownership

`Application::new(routes)` is inert and requires the route capability at construction.
`start` validates HTTP assembly before binding, registers the bound listener under protected startup, and returns only after component readiness.
`start_with_signals` explicitly adds process-level SIGINT/SIGTERM ownership; plain `start` does not change process signal handling.
`run` is the process-entrypoint convenience that starts with those signals and awaits checked completion.
No health routes are exposed unless `Application::actuator(...)` explicitly attaches an inert plan.
Attachment reserves the complete `/actuator` subtree through upstream route-inventory overlap checks before binding.
The removed framework `/live` and `/ready` routes have no aliases and are no longer reserved.
Lifecycle readiness means application approval, a running driver and initialized components, not a fabricated dependency-health claim.

Actuator registers ordinary core `HealthMonitor` components through protected registration.
Each monitor acknowledges startup before its first probe completes, so startup can succeed with readiness still unavailable.
Liveness never reads external contributors; readiness includes only contributors explicitly assigned to it, while overall health includes all contributors.
Endpoint reads synchronously aggregate bounded in-memory observations and read lifecycle last so an observed drain overrides earlier successes.
Unknown, failure, timeout, staleness and writer stop all contribute `DOWN`.
Boot maps sanitized typed results to fixed JSON, HTTP 200/503 and `Cache-Control: no-store`.

The generic web `PublicReadSubtree` extension fills an upstream composition gap without adopting upstream source or introducing Actuator semantics into web.
It uses an upstream validation-only route group to reserve a subtree, then dispatches application paths through the sealed upstream boundary client.
Public routes use upstream operational observation, while application dispatch retains the existing observer after its own routing has matched the correct route template.
Both paths emit one completion with the same server correlation used in their responses.
Its assembled type exposes only supervised registration, never a router escape.
Concrete contributor failures live in a separate trusted diagnostics capability, not in endpoint reader snapshots, including during concurrent replacement.
No request read formats a retained cause or destroys an application error value.

`RunningApplication` retains native running ownership and exposes read-only status and completion observation.
Cancelling a borrowed `wait` does not cancel the driver.
Consuming `shutdown` requests drain and awaits checked completion, preserving native shutdown failures.
Dropping the running owner requests shutdown but is not proof of completion; an observer can await retained settlement separately while the runtime remains alive.
No general asynchronous Drop or runtime-death cleanup guarantee is implied.

The initial bootstrap uses explicit framework defaults: 15-second startup, 10-second drain, 2-second abort observation and bounded cleanup.
The response-construction budget defaults to 30 seconds and can be replaced with an already validated budget.
These are operational defaults, not external-provider deadlines or bounds on arbitrary detached tasks and response-body streaming.
Response-construction expiry preserves the upstream HTTP contract: status 503 with problem code `deadline_exceeded`.
Startup and shutdown error formatting follows the underlying typed redaction contracts, not a blanket guarantee over arbitrary application errors.

## Selective source adoption

Dependencies are the default integration mechanism.
When the supported interface cannot enforce an agreed invariant, assess the ownership gap before adding more application coordination.
For atomic durable completion, the upstream pool-owning API could not share its commit with domain changes.
The source extension now makes domain SQL a required callback to success, continuation and failure completion inside the existing atomic machinery.
It retains savepoint recovery, fail-fast policy, native lifecycle effects and unconfirmed-commit uncertainty.
The import is maintained directly in `butter-workflow`, not hidden behind an extra native package or a second queue implementation.
Upstream copyright, schema identities and source provenance remain explicit even though product naming belongs to Butter.

## Non-goals of the bootstrap

There is no DI container, procedural-macro DSL, global subscriber, generic repository, new queue engine or automatic infrastructure provisioner.
HTTP security integration, identity storage, object storage, telemetry assembly and worker-runtime bootstrapping require their own real consumer contracts before implementation.
The bootstrap does not change any application's current database, identity provider, deployment or worker authority boundary.
