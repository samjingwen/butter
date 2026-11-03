# Butter change delivery

This policy belongs to Butter and applies to this repository and its explicitly assigned implementation worktrees.
Read it together with `AGENTS.md`, the crate documentation, and the source-provenance contracts.
Do not depend on an instruction file in a parent workspace.

## Scope and authority

Own the applicable delivery sequence: dedicated Worktrunk worktree -> requirements and implementation -> executable verification and review -> GitHub PR -> protected merge -> safe local primary-branch synchronization.
Commit intended changes, push the feature branch, open the PR, and merge once required checks and reviews pass.
Explicit Plan, review-only, PR-only, human-review, runtime, publication, and production limits take precedence.
No crates.io publication or deployment is configured or authorized by the bootstrap.
Do not invent a release target or treat source delivery as runtime acceptance.

The user retired no-mistakes gates and configuration.
Do not initialize, install, invoke, or restore that gate here.
Its retirement does not waive quality checks, independent review, GitHub protections, or unresolved acceptance requirements.

## Isolate and implement

- Inspect status, worktrees, the actual default branch, and active ownership before editing.
- Read `wt switch --help` and inspect setup hooks before creating a dedicated implementation worktree with Worktrunk.
- Fetch the intended base or use the base explicitly selected for the task.
- Use the returned worktree path and verify the actual directory, branch, and base before editing.
- Continue related work in its existing worktree without borrowing another task's changes.
- Preserve uncommitted work, other sessions, retained evidence, private local material, and persistent data.
- Keep core independent of web, data, and workflow; preserve upstream provenance, licenses, and failure tests.
- Do not implement another async runtime, database, queue, or identity provider as a tooling side effect.
- Preserve applied SQL migrations and regenerate SQLx metadata and Cargo.lock through their owning tools.
- Never hand-edit generated files or `CHANGELOG.md`.
- Never read private environment files or authentication caches, and never commit credentials or machine-local records.

## Verify and review

- Run `bash scripts/check.sh` for formatting, strict Clippy, package tests, doctests, and rustdoc.
- Use `bash scripts/check-workflow.sh` only with its owned disposable PostgreSQL 18 fixtures and the task's runtime authority.
- Do not substitute production databases or silently provision shared infrastructure.
- Keep pinned toolchains, locked dependencies, meaningful compiler/static-analysis checks, and real behavioral tests.
- Reproduce reported bugs through their user-facing path before fixing them.
- Preserve failing evidence, fix causes rather than weakening checks, and rerun verification invalidated by each fix.
- Apply only tools appropriate to maintained languages; do not install unrelated toolchains.
- Review the complete base-to-head diff with the installed Hardlook skill and record coverage, findings, and limitations.
- Inspect real configured CI and required reviews; missing, pending, failed, or incomplete evidence is not a pass.
- Claim Linux/macOS validation only when it was actually executed.

## Deliver and synchronize

- Review status, all intended commits, and the full diff; stage only this task's files.
- Prefer `gh-axi` for GitHub operations, with `gh` as a fallback.
- Include decisions, verification, limitations, and any compatibility notes in the PR.
- Satisfy latest-head required checks, reviews, and conversation resolution without bypassing protections.
- Merge through GitHub and verify the actual merged state and exact merge SHA.
- Recheck the default-branch worktree for dirty/untracked/ignored collisions and active ownership before synchronization.
- Pull the actual default branch with fast-forward-only semantics when safe; never stash, reset, clean, force refs, or rebase local divergence to make it succeed.
- Verify local default HEAD equals the freshly fetched remote tip and contains the merge, retaining later remote commits.
- Report a concrete synchronization blocker rather than overwriting another task's state.
- Report the PR, merge SHA, checks, primary path/branch/SHA, and any separately authorized release outcome honestly.
