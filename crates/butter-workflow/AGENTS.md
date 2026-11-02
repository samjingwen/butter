# Maintained durable persistence

Read `../../sources/PROVENANCE.md` and the root guide before editing.
This is maintained source, not an immutable vendor directory or a replacement queue implementation.
The maintained implementation belongs directly to `butter-workflow`; PostgreSQL schema contracts retain their native identities.

## Ownership

Atomic composition lives in `src/atomic.rs` and `src/atomic/`.
Queue lifecycle effects live in `src/jobs/queue/lifecycle/` and share private transactional SQL dispatch with pool-owning entrypoints.
Workflow persistence and propagation live in `src/jobs/workflows/`.
Native failure contracts live in `tests/`, including `atomic_completion`, `atomic_runner` and `commit_acknowledgement`.

## Invariants

Retain upstream license notices and provenance.
Never rewrite applied migrations or manually edit generated SQLx metadata.
Keep all three migration copies identical when adding forward-only schema changes.
Never expose a replaceable native transaction to bypass the protected atomic owner.
Unconfirmed commit, scope loss and cancellation do not establish rollback or replay permission.
Keep attempts, events, retry/dead-letter state and workflow propagation coupled to queue mutations.
Domain generation, authorization, cancellation and accounting policy stay in applications.

## Verification

Run `bash scripts/check-workflow.sh` from the Butter root with the intended Docker endpoint.
Missing Docker must fail, not silently skip these native tests.
The ordinary root gate also compiles this package and runs its Rustdoc.
