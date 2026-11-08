# Verification

## Reproducible commands

Use the toolchain selected by `rust-toolchain.toml` and the Cargo-generated lockfile.
Run `bash scripts/check.sh` for the ordinary framework gate and `bash scripts/check-workflow.sh` for disposable PostgreSQL persistence acceptance.
CI runs the ordinary gate on Linux and macOS and the Docker-backed workflow gate on Linux.
Configured CI is not evidence that a particular hosted execution passed.

The bootstrap's public HTTP tests use real loopback TCP, not an in-memory-only router mock.
They cover startup readiness, application/Actuator responses, listener release, reserved-subtree refusal, occupied ports, response-construction deadlines, borrowed-wait cancellation, owner drop and graceful completion of admitted work.
Actuator acceptance covers GET/HEAD JSON and headers, method rejection, query inertness, explicit attachment, feature-unified no-attachment, removed legacy routes, multiple readiness contributors, overall-only membership, outage/timeout recovery, blocked probes, local error retention and response redaction.
Loopback regressions also cover trailing-slash subtree reservation and fallback isolation, application route templates on spans/completions, exactly one completion per request and consistent server correlation.
Core-backed Actuator tests exercise every contributor state, exact freshness expiry, the lifecycle matrix, final lifecycle precedence, sequential sampling, cancellation and writer invalidation with controlled Tokio time.
Both Boot feature states are tested; the source-graph gate compiles seven facade combinations and checks real empty defaults and component independence.
The compiled example's smoke tests independently send SIGTERM and SIGINT and require exit status zero.
The source graph check executes Cargo's actual feature graphs rather than inspecting manifest strings alone.
Strict rustdoc runs cover both the minimal facade and all implemented components.

The workflow suite retains native attempts, events, migrations, lock ordering, leases, continuations, retries/dead letters and workflow propagation tests.
Atomic-completion tests additionally cover coupled domain writes and completion, rejection recovery, stale/expired authority, concurrent completion, cancellation, policy selection, unsupported transaction escape and actual lost database commit acknowledgement.
The wire fault observes PostgreSQL's completed COMMIT, drops its reply before SQLx receives it, and checks the durable domain and queue result independently.
That is distinct from the deferred-trigger commit-error control and discarding an already acknowledged application reply.

## Evidence boundaries

Verification from the original Batter worktree predates this package layout and dependency graph.
It does not qualify the Butter import automatically.
Actual bootstrap outcomes are recorded in the reviewed pull request and its checks.
The remaining upstream dependency packages are not re-run as full test roots by these gates; their integration is exercised through Butter's actual consumers.
Neither these gates nor the source import establish a downstream application's worker protocol or exactly-once external effects.
No private environment files, production fixtures or retained application databases are required.
Actuator checks use synthetic contributors and do not establish a consumer's database/schema checks, credentials, deployment health-check configuration or network policy.
Real consumer validation remains a separate acceptance step; the experimental generic API is not a publication or stability claim.
