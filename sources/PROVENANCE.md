# Maintained source provenance

Butter normally consumes upstream projects as dependencies.
Source is maintained here only where a concrete extension requires ownership of that implementation.
Public product naming does not remove upstream copyright or license obligations.

## Durable persistence

`../crates/butter-workflow/` comes from `runledger/runledger-postgres` in [bpcakes/batter](https://github.com/bpcakes/batter) at revision `45b451b3b9b628be1010095c92859b7d42b9e157`.
That code descends from the Runledger import documented in the preserved historical `IMPORT.md`.
The upstream MIT licenses remain in `LICENSE`, `../crates/butter-workflow/LICENSE` and the migration-fixture directory.
The preserved upstream README describes that original ecosystem, not Butter's implemented package inventory or executed verification.

The imported snapshot includes the locally authored additive atomic-completion extension previously prepared in a dedicated Batter fork worktree.
That extension adds mandatory domain-SQL callbacks to queue-phase success, continuation and failure completion, preserving native persistence and uncertain-commit behavior.
Its original worktree was not committed or pushed before this import; Butter's reviewed commit will be the independently consumable source revision.
`initial-snapshot.json` records SHA-256 hashes of all imported source, tests, migration, SQLx metadata and license assets before Butter packaging adaptations.
It is generated provenance evidence, not a list to update manually as the maintained code evolves.

The initial packaging changes replace workspace dependency declarations with Butter's declarations and place the implementation directly in unpublished `butter-workflow`.
Rust imports and Rustdoc examples use `butter_workflow`; the redundant extra native persistence package and forwarding crate are not retained.
The package retains the upstream persistence lint thresholds from `runledger/clippy.toml`.
In the snapshot record, `runledger-postgres/` paths map to `../crates/butter-workflow/` before those packaging adaptations.
Applications consume that implementation through `butter-workflow` or `butter::workflow`.
Database object names, applied migration content and native model types are not renamed for branding.

The migration directories here retain the canonical and test-fixture copies required by the imported equality tests; the maintained package embeds its own matching copy.
They are schema sources, not database data or an alternate provisioner.
The model, test support, SQLx foundation and operational HTTP/lifecycle libraries remain dependencies pinned to the same upstream revision.
Butter does not currently include Runledger's worker runtime or TUI.

## Verification boundary

Tests executed in the original worktree do not establish the Butter source graph's correctness.
Butter must run its own compile, lint, Rustdoc, consumer and disposable-PostgreSQL checks after dependency resolution and packaging.
No application database, production fixture, private configuration or upstream tracker is imported.
