# Verification

## Reproducible commands

Use the toolchain selected by `rust-toolchain.toml` and the Cargo-generated lockfile.
Run `bash scripts/check.sh` for the host ordinary framework gate and `python3 scripts/test-worktree-cache.py` for the host Worktrunk cache-policy gate.
Run `bash scripts/check-linux.sh` for both gates in digest-pinned Ubuntu 24.04 `linux/amd64`.
Run `bash scripts/check-workflow.sh` for disposable PostgreSQL persistence acceptance.
No remote CI workflow is configured, so exact-head local command results and the Hardlook review are the delivery evidence.

On the maintained macOS delivery path, the workflow Rust test process runs on macOS while its owned PostgreSQL 18 fixtures run in Linux containers.
The Ubuntu quality image runs compilation, Clippy, ordinary tests, doctests, rustdoc, feature graphs, HTTP smoke tests and Worktrunk cache tests.
It intentionally does not run the main `butter-workflow` integration suite, so this sequence does not prove Linux execution of that Rust test process.

The bootstrap's public HTTP tests use real loopback TCP, not an in-memory-only router mock.
They cover startup readiness, application/Actuator responses, listener release, reserved-subtree refusal, occupied ports, response-construction deadlines, borrowed-wait cancellation, owner drop and graceful completion of admitted work.
They also cover protected initializer ordering, failed-startup rollback, cleanup after HTTP drain, bounded cleanup and checked cleanup-failure propagation.
Actuator acceptance covers GET/HEAD JSON and headers, method rejection, query inertness, explicit attachment, feature-unified no-attachment, removed legacy routes, multiple readiness contributors, overall-only membership, outage/timeout recovery, blocked probes, local error retention and response redaction.
Loopback regressions also cover trailing-slash subtree reservation and fallback isolation, application route templates on spans/completions, exactly one completion per request and consistent server correlation.
Core-backed Actuator tests exercise every contributor state, exact freshness expiry, the lifecycle matrix, final lifecycle precedence, sequential sampling, cancellation and writer invalidation with controlled Tokio time.
Boot's ordinary, Actuator and web-security feature states are tested; the source-graph gate compiles eleven facade combinations and checks real empty defaults and component independence.
The security-core matrix covers provider fallback, terminal rejection, unsupported mechanisms, cancellation, credential redaction and zeroization, logical disjunction, explicit deny-overrides composition and all-abstain denial.
Web-security loopback acceptance covers multiple first-match chains, malformed and conflicting credentials, neutral failures, unmatched denial, context isolation, cancellation under Butter's response deadline, Actuator coexistence and checked listener shutdown.
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
