# Butter

Rust application development, smooth like butter.
Inspired by Spring Boot's cohesive startup experience, built around explicit Rust ownership and reusable capabilities.

## Start

```sh
git clone https://github.com/samjingwen/butter.git
cd butter
cargo run -p butter --example hello --features web,actuator
```

The example prints its bound address and serves `GET /` and explicitly attached Actuator health on `127.0.0.1:8080`.
`GET` and bodyless `HEAD` are available at `/actuator/health`, `/actuator/health/liveness` and `/actuator/health/readiness`.
Stop it with Ctrl-C or SIGTERM for checked graceful shutdown.
To select another explicit listener, set `BUTTER_HTTP_ADDR`, for example `BUTTER_HTTP_ADDR=127.0.0.1:0` for an OS-assigned port.
It does not read `.env` files, start a database, install a global logging subscriber or expose a public interface by default.

```rust,no_run
use butter::{Application, actuator::Actuator, web::{Router, routing::get}};

#[tokio::main]
async fn main() -> Result<(), butter::core::BoxError> {
    let routes = Router::new().route("/", get(|| async { "Hello, Butter!" }));
    let _completed = Application::new(routes)
        .actuator(Actuator::builder().build())?
        .run().await?;
    Ok(())
}
```

The application owns its Tokio runtime and domain behavior.
Butter owns protected HTTP assembly, component readiness, request admission and the startup-to-shutdown sequence.
There is no runtime class scanning, DI container or hidden database initialization.

## Components

| Package | Bootstrap responsibility |
| --- | --- |
| `butter` | Feature-selected application facade; defaults select core only. |
| `butter-core` | Lifecycle, configuration, deadlines, cancellation and cleanup primitives. |
| `butter-actuator` | Transport-independent health with explicitly selected supervised contributors. |
| `butter-boot` | Inert application assembly, startup, readiness and checked shutdown. |
| `butter-web` | Protected HTTP routing with native Axum handlers. |
| `butter-data` | PostgreSQL session/transaction capabilities and native SQLx queries. |
| `butter-workflow` | Maintained durable persistence with atomic domain/job completion. |

Enable `web`, `actuator`, `data` or `workflow` explicitly on the facade when needed; `workflow` implies `data`.
`actuator` alone selects no HTTP stack, and HTTP-only applications do not inherit SQLx or workflow persistence.
Even with `web,actuator` compiled, routes require explicit `Application::actuator(...)` attachment.
The removed framework `/live` and `/ready` paths have no aliases; consumers must migrate their health-check paths with their Butter revision.
See [Actuator usage and compatibility](docs/actuator.md) and the [accepted design](docs/planning/actuator/README.md).
`butter-security`, `butter-storage`, `butter-observability` and `butter-test` remain intended component names, not implemented packages.
The proposed Butter Security architecture is documented in the [security planning index](docs/planning/security/README.md).
Worker-runtime integration is also pending; the workflow package currently implements persistence and atomic composition, not automatic worker startup.

## Dependencies and source ownership

Use upstream projects as dependencies by default.
Maintain source inside the owning Butter component only when a concrete fix or extension needs it.
Here, `butter-workflow` contains the durable-persistence source with our atomic-completion extension; there is no separate native persistence workspace package or forwarding workflow crate.
Axum, Tokio, SQLx, the operational foundation and durable model/test-support libraries remain dependencies.
The related upstream foundation/model packages resolve from one immutable revision, never a mutable sibling checkout or a moving fork branch.

The extension checks current lease authority, invokes required domain SQL and applies native completion in one protected transaction.
Application generation, authorization, cancellation and accounting policy remain application-owned.
An unconfirmed commit is uncertainty, not rollback proof or permission to repeat a provider action.
See [source provenance](provenance/PROVENANCE.md), [architecture](docs/architecture.md) and [verification](docs/verification.md).

## Check

```sh
bash scripts/check.sh
bash scripts/check-workflow.sh
```

The first command checks formatting, strict Clippy, feature isolation, ordinary package tests, all doctests, rustdoc and real HTTP process smoke tests.
The second runs the retained persistence suite against native test-harness-owned disposable PostgreSQL 18 through Docker.
Missing Docker is a failure, not a silently skipped workflow gate.
On macOS Docker Desktop, select the intended socket explicitly if needed: `DOCKER_HOST=unix://$HOME/.docker/run/docker.sock bash scripts/check-workflow.sh`.

Development is pinned to Rust 1.99.1, checked against the official stable manifest when bootstrapped.
See [worktree caches](docs/worktrees.md) for safe, optional dependency-cache reuse when creating Worktrunk worktrees.
Linux and macOS are the initial validation targets.
The API is experimental and packages are not published to crates.io.
No application migration, production deployment or package release is included.

## License

Butter's original code is MIT licensed.
Adapted source retains its upstream MIT notices and recorded provenance; dependency licenses remain their own.
