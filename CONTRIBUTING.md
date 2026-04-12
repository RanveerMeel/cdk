# Contributing to CDK

Thanks for helping improve CDK.

## Contribution Workflow

1. Fork and create a topic branch from `master`.
2. If the change is non-trivial, open an issue first and align on approach.
3. Implement the change with focused commits that follow the commit standard.
4. Run local validation before opening a PR.
5. Open a PR with a clear problem statement, change summary, and test notes.

## Local Validation Checklist

Run these before requesting review:

```bash
cargo check --target x86_64-unknown-none
./run_qemu.sh
```

If your change touches host tools, also run:

```bash
cargo check
```

## Pull Request Expectations

- Keep PRs small and reviewable.
- Link related issues in the PR description.
- Document kernel behavior changes in `README.md` or `ARCHITECTURE.md`.
- Include console output or test evidence for non-trivial fixes.
- Resolve review comments with follow-up commits (avoid force-push rewrite during active review unless requested).

## Hard Commit Policy

All commits must pass `tools/validate_commit_msg.sh`.

Required format:

```text
type(scope): short imperative summary
```

Rules are intentionally strict:

- Allowed `type`: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`
- `scope` is mandatory and must be lowercase kebab-case
- Subject length must be 15-72 characters
- Subject must start lowercase and not end with `.`
- `WIP`, `tmp`, `fixup!`, and `squash!` are blocked
- `feat`, `fix`, and `refactor` must include a body

Install hooks once:

```bash
./tools/install_git_hooks.sh
```
