# Contributing

For a larger change, please open an issue first so we can agree on the approach.

- Keep the agent small. CI checks memory, CPU and image size with `scripts/agent-budget.sh`.
- Jobs are data, never code. A new job or result field goes into `crates/agent/src/schema.rs`, and a new result field also into `docs/agent-security.md`.
- Response bodies, header values and cookies never leave the network.
- Add tests for what you change. Before you open a pull request, run `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo test --workspace --all-features`. For changes in `sandbox/`, also run `npm run typecheck` and `npm test` there. New dependencies must pass `cargo deny check` (licenses and advisories in `deny.toml`).

By contributing, you agree that your contribution is licensed under the Apache License 2.0.

## Pull request titles

Pull requests are squash-merged. The title becomes the commit on `main` and a line in the changelog, so write it for the people who run the agent. It follows [Conventional Commits](https://www.conventionalcommits.org/), and CI checks it:

```text
fix(checks): match a DNS TXT expected value against the whole record
```

- `feat` makes a minor release and `fix` a patch release. `perf` and `revert` also show in the changelog. `docs`, `test`, `refactor`, `build`, `ci`, `chore` and `style` release nothing.
- `!` after the type, or a `BREAKING CHANGE:` footer, makes a major release.
- Scopes: `agent`, `checks`, `browser`, `sandbox`, `chart`, `docs`, `deps`. Changes under `charts/` release the chart; everything else releases the agent.
- Use the imperative, lower case, no full stop. No tracker ids; link GitHub issues instead.

Versions, changelogs and tags are made by release-please. Don't change them by hand.
