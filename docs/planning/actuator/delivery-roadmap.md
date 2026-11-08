# Butter Actuator delivery roadmap

## Delivery rule

Actuator is delivered in reviewed vertical slices that preserve a usable feature graph and do not publish partially migrated probe contracts.
Each implementation slice includes source, tests, rustdoc, compatibility notes and complete local verification on the exact reviewed commit.

## Phase 0: architecture acceptance

- Review this planning set.
- Confirm package ownership, optional dependency direction and non-goals.
- Prototype the smallest internal typed operation catalog without stabilizing arbitrary custom endpoints.
- Prototype contributor error erasure and a capability-based local diagnostics handle.

Acceptance requires agreement that Actuator remains transport-independent, web remains independent and Boot performs only optional HTTP mapping.

## Phase 1: feature and Actuator core

- Change the facade default feature set to empty.
- Add `butter-actuator` and `butter::actuator` behind the optional `actuator` feature.
- Add validated endpoint and contributor identities.
- Add the typed health endpoint and overall, liveness and readiness views.
- Add explicit contributor group membership and deterministic aggregation.
- Integrate continuous probes with Butter core health monitors and supervisor registration.
- Add safe local diagnostics without automatic cause formatting.

Acceptance requires the full feature-isolation matrix, aggregation state matrix, cancellation tests, redaction tests, doctests and rustdoc.

## Phase 2: Boot HTTP integration and route transition

- Add Boot's optional `actuator` dependency and feature.
- Add explicit `Application::actuator` composition.
- Map the three health operations through the protected HTTP boundary.
- Reserve the `/actuator` subtree when Actuator is attached.
- Remove framework `/live` and `/ready` routes without aliases.
- Update the hello example, smoke script, architecture documentation and verification documentation.

Acceptance requires real loopback coverage, legacy-path 404 coverage, conflict refusal before bind, bounded response behavior and checked shutdown settlement.
Phases 1 and 2 may share one pull request if that is necessary to keep every commit and reviewed head coherent.

## Phase 3: downstream validation

- Integrate one confidential downstream application through an immutable Butter revision.
- Keep its dependency names, schemas, credentials, endpoints and operational details outside the public Butter repository.
- Exercise at least two independent readiness contributors and one overall-only synthetic contributor.
- Generalize only mechanisms demonstrated reusable by the integration.

Acceptance requires an unavailable dependency transition, restored readiness, stale observation, bounded shutdown and no confidential downstream information in Butter history or review evidence.

## Deferred expansion

Custom health groups, contributor detail authorization, a separate management listener, configurable paths, metrics, information endpoints, environment inspection, log management, audit events, shutdown operations and additional transports require separate reviewed plans.
Database-specific contributor packages require repeated generic demand and must not create a hidden dependency from Actuator into `butter-data`.

## Maturity gate

Butter Actuator remains experimental and unpublished until:

- The endpoint and contributor contracts survive a real consumer integration.
- Feature isolation passes for every supported combination.
- Failure redaction and route-conflict behavior have adversarial tests.
- The documented macOS and pinned-Ubuntu local quality gates pass on the exact reviewed implementation commit.
- Public documentation states the snapshot, cancellation and dependency-policy limitations.

No crate publication, broad management API or compatibility guarantee is authorized by this plan.
