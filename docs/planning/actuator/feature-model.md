# Butter feature model and compatibility

## Facade defaults

The `butter` facade should change from a default `web` feature to an empty default feature set.
Every capability beyond core becomes an explicit selection.

The planned facade graph is equivalent to:

```toml
[features]
default = []
web = ["dep:butter-web", "dep:butter-boot"]
data = ["dep:butter-data"]
workflow = ["dep:butter-workflow", "data"]
actuator = ["dep:butter-actuator", "butter-boot?/actuator"]
```

`butter-core` remains the facade's only unconditional component dependency.
The optional dependency from the facade to `butter-actuator` exposes it as `butter::actuator`.

## Component features

`butter-boot` keeps its existing direct dependency on `butter-web`.
It adds an empty default feature set and an `actuator` feature equivalent to:

```toml
[features]
default = []
actuator = ["dep:butter-actuator"]
```

The `?` forwarding syntax on the facade enables Boot's Actuator integration only when Boot is already selected through `web`.
Selecting facade `actuator` alone therefore does not pull in Boot, Axum, a listener or web routing.
Selecting facade `web` alone does not pull in Actuator.

## Required isolation

| Selected facade features | Required result |
| --- | --- |
| None | Core only |
| `web` | Web and Boot without Actuator, SQLx or workflow |
| `data` | Data without web, Boot, Actuator or workflow |
| `workflow` | Workflow and data without web, Boot or Actuator |
| `actuator` | Core and transport-independent Actuator without web or data |
| `web`, `actuator` | Boot web integration for an explicitly attached Actuator |
| `web`, `data`, `actuator` | HTTP, PostgreSQL capability and Actuator without workflow |

No feature selects `workflow` except `workflow` itself.
No feature selects `data` except `data` and `workflow`.
Actuator does not acquire database-specific contributors from `data` automatically.

## Runtime activation

Cargo feature selection controls compilation, not endpoint exposure.
An application must both compile `web` and `actuator` and call `Application::actuator` to expose the HTTP routes.
This rule prevents a transitive dependency from changing route behavior through Cargo feature unification.

A non-web application can select only `actuator`, register the Actuator plan in its Butter core protected startup and invoke the running typed operations in process.
The first slice does not provide another transport adapter for that application.

## Consumer migration

The empty default feature set is a source compatibility change for consumers that currently rely on `butter` defaults.
HTTP consumers migrate from an implicit default to an explicit dependency:

```toml
butter = { git = "https://github.com/samjingwen/butter", rev = "<reviewed-commit>", features = ["web"] }
```

Consumers adding Actuator select both capabilities and attach it during application construction:

```toml
butter = { git = "https://github.com/samjingwen/butter", rev = "<reviewed-commit>", features = ["web", "actuator"] }
```

Consumers using immutable Git dependencies update to one reviewed revision containing the entire feature and route transition.
They must not combine a facade from one revision with Boot or Actuator components from another.

The route migration is intentionally direct:

| Removed framework route | Replacement |
| --- | --- |
| `/live` | `/actuator/health/liveness` |
| `/ready` | `/actuator/health/readiness` |

No alias period is planned because aliases increase the permanent public surface and can hide incomplete operator migration.
Downstream health checks, deployment manifests, tests and documentation must change atomically with their Butter revision.

## Compatibility discipline

The crates remain unpublished and experimental, but the change still requires explicit migration notes and feature-graph tests.
The implementation must not represent the old routes as deprecated and still active.
The facade must not retain `web` in its default set for convenience after accepting the empty-default decision.
Future capabilities must remain opt-in unless a separate compatibility review changes this policy.
