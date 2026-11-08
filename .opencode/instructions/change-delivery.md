# Butter change delivery

This policy belongs to Butter and applies to this repository and its explicitly assigned implementation worktrees.
Read it together with `AGENTS.md`, the crate documentation, and the source-provenance contracts.
Do not depend on an instruction file in a parent workspace.

## Scope and authority

Own the applicable delivery sequence: dedicated Worktrunk worktree -> requirements and implementation -> executable verification and Hardlook review -> GitHub PR -> protected merge -> safe local primary-branch synchronization.
Commit intended changes, push the feature branch, open the PR, and merge once required checks and reviews pass.
Plan, review-only, PR-only, human-review, native-runner, runtime, publication, production, and data-retention limits take precedence.
No crates.io publication or deployment is configured or authorized by the bootstrap.
Do not invent a release target or treat source delivery as runtime acceptance.

The user retired no-mistakes gates and configuration.
Do not initialize, install, invoke, or restore that gate here.
Remote CI is not configured.
GitHub Actions remains repository-enabled for possible future use, but GitHub is currently the source-review and merge boundary, not a cloud builder.
Tool retirement and absent remote CI do not waive executable quality checks, independent review, GitHub protections, or unresolved acceptance requirements.

## Isolate and implement

- Inspect status, worktrees, the actual default branch, and active ownership before editing.
- Read `wt switch --help` and inspect setup hooks before creating a dedicated implementation worktree with Worktrunk.
- Fetch the intended base or use the base explicitly selected for the task.
- Use the returned worktree path and verify the actual directory, branch, and base before the first edit.
- Continue related work in its existing worktree without moving or borrowing another task's uncommitted changes.
- Preserve uncommitted work, other sessions, retained evidence, private local material, and persistent data.
- Keep core independent of web, data, and workflow; preserve upstream provenance, licenses, and failure tests.
- Do not implement another async runtime, database, queue, or identity provider as a tooling side effect.
- Preserve applied SQL migrations and regenerate SQLx metadata and Cargo.lock through their owning tools.
- Regenerate generated output with its owning tool; never hand-edit it or `CHANGELOG.md`.
- Never read private environment files or authentication caches or commit credentials and machine-local records.

## Verify and review

- Run `bash scripts/check.sh` for formatting, strict Clippy, package tests, doctests, and rustdoc.
- Run `python3 scripts/test-worktree-cache.py` for native Worktrunk cache-policy regressions.
- Run `bash scripts/check-linux.sh` for the ordinary and Worktrunk cache gates in pinned Ubuntu 24.04 `linux/amd64`.
- Use `bash scripts/check-workflow.sh` only with its owned disposable PostgreSQL 18 fixtures and the task's runtime authority.
- Do not substitute production databases or silently provision shared infrastructure.
- Keep pinned toolchains, locked dependencies, meaningful compiler/static-analysis checks, and real behavioral tests.
- Reproduce reported bugs through their user-facing path before fixing them.
- Preserve failing evidence, fix causes rather than weakening checks, and rerun verification invalidated by each fix.
- Apply only tools appropriate to maintained languages; do not install unrelated toolchains.
- Review the complete base-to-head diff with the installed Hardlook skill and record coverage, findings, and limitations.
- A partial review, failed test, unavailable tool, or passing rerun without a substantiated fix is not clean acceptance.
- Record that the Ubuntu quality image does not execute the main `butter-workflow` integration suite unless a separately authorized Linux workflow-runtime gate actually ran.
- Claim Linux or macOS validation only for the gates actually executed on that platform.

## Deliver and synchronize

- During initial inspection, record the actual default branch and the primary checkout path that owns it; do not hardcode a machine-specific path or rediscover it with `wt switch` during final session return.
- Review status, all intended commits, and the full diff; stage only this task's files.
- Prefer `gh-axi` for GitHub operations, with `gh` as a fallback.
- Include decisions, exact-head local evidence, limitations, and any compatibility notes in the PR.
- Satisfy actual required checks, reviews, and conversation resolution without bypassing protections; do not invent hosted checks for this no-CI project.
- Merge through GitHub and verify the actual merged state and exact merge SHA.
- Inspect the default-branch worktree's dirty/untracked/ignored collisions and active ownership before synchronization.
- Pull the actual default branch with fast-forward-only semantics when safe; never stash, reset, clean, force refs, or rebase local divergence to make it succeed.
- Preserve user-owned untracked files and report any resulting collision or synchronization blocker.
- Verify local default HEAD equals the freshly fetched remote tip and contains the merge, retaining later remote commits.
- If primary synchronization is blocked, remain in the implementation worktree and report the blocker without moving the OpenCode session.
- After primary synchronization succeeds, return the current OpenCode session to the recorded primary checkout path with `opencode.session_move`; do not use `wt switch`, `cd`, shell integration, or a new OpenCode process as a substitute.
- If the session is already in the primary checkout, skip `opencode.session_move` and perform the same post-move verification.
- Call `opencode.session_move` alone at a safe execution boundary because the directory change applies at the next boundary; do not run destination-dependent tools in the same execution call.
- After OpenCode reports the directory change, use a separate tool call to verify the current directory is the recorded primary checkout, the active branch is the default branch, HEAD equals the freshly fetched remote tip, and the merged revision is an ancestor of HEAD.
- Recheck status after the move and report unexpected or preserved files without modifying them.
- If `opencode.session_move` fails, remain in the implementation worktree and report the blocker.
- Do not remove the implementation worktree automatically after returning the session.
- Report the PR, merge SHA, checks, primary path/branch/SHA, and any separately authorized release outcome honestly.
