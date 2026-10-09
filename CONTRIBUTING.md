# Contributing

Thank you for helping. Before you start on a larger change, open an issue so we can agree on the approach.

- Keep the agent small: the resource budget (memory, CPU, image size) must hold; CI checks it with `scripts/agent-budget.sh`.
- Jobs are data, never code. A new job field goes into the fixed schema in `crates/agent/src/schema.rs`, and a new result field into the result fields there and into `docs/agent-security.md`.
- No response bodies, header values or cookies may leave the network.
- Add tests for what you change, and run `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo test --workspace --all-features` before you open a pull request. A change in `sandbox/` also needs `npm run typecheck` and `npm test` there.

By contributing you agree that your contribution is licensed under the Apache License 2.0.

## Pull requests and commits

Pull requests are squash-merged, so the pull request title becomes the commit on `main` and one line in the changelog. The title follows [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <summary>`, for example `feat(checks): resolve CAA records` or `fix(agent): retry the connect after a proxy error`. CI checks it.

- Types that reach the changelog: `feat` (a minor release), `fix` (a patch release), `perf` and `revert`. `docs`, `test`, `refactor`, `build`, `ci`, `chore` and `style` release nothing. A `!` after the type or scope (`feat(checks)!: …`) or a `BREAKING CHANGE:` footer makes a major release.
- Scopes: `agent`, `checks`, `browser`, `sandbox`, `chart`, `docs`, `deps`. Changes under `charts/` release the chart; everything else releases the agent.
- Write the summary for the people who run the agent: what changes for them, in the imperative, lower case, without a full stop. Explain why in the body when it is not obvious.
- No ticket or issue tracker ids such as `ABC-123`. Refer to a GitHub issue or pull request by its link instead.

Releases are made from these commits by release-please; never change a version, a changelog or a tag by hand.
