# Contributing to CDK

Thanks for helping improve CDK — an open-source, quantum-safe agent trust
kernel. Read [ROADMAP.md](ROADMAP.md) to see where the project is heading and
which milestones are open.

## Before your first contribution

1. **Sign the CLA.** All contributions are accepted under the
   [CDK Contributor License Agreement](CLA.md). In your first pull request,
   comment:

   ```text
   I have read the CDK Contributor License Agreement (CLA.md, version 1.0) and I hereby sign it.
   ```

   You keep your copyright. The CLA lets the project also ship your code in
   commercial editions, and guarantees it stays available here under
   Apache-2.0.
2. **Sign off every commit** with `git commit -s` (Developer Certificate of
   Origin).
3. **Report vulnerabilities privately** — see [SECURITY.md](SECURITY.md).
   Never open a public issue for a security bug.
4. **Never submit classified, export-restricted, or confidential material.**

## Contribution Workflow

1. Fork and create a topic branch from `main`.
2. If the change is non-trivial, open an issue first and align on approach.
3. Implement the change with focused commits that follow the commit standard.
4. Run local validation before opening a PR.
5. Open a PR with a clear problem statement, change summary, and test notes.

## Branch and PR Policy

- Direct pushes to `main` are blocked by the local `pre-push` hook.
- Always push a non-main branch and open a Pull Request into `main`.
- Recommended branch naming: `feat/*`, `fix/*`, `docs/*`, `chore/*`.

## Local Validation Checklist

Run these before requesting review:

```bash
cargo build                        # kernel, debug
cargo build --release --bin cdk    # kernel, release
cargo check --features virtio-hw   # hardware probe paths
cargo test-host                    # host unit tests
tools/build_user_programs.sh       # user programs + ramdisk (user/)
(cd user/ml && cargo test --target x86_64-unknown-linux-gnu)   # inference runtime
python3 tools/train_demo_model.py && git diff --exit-code user/models  # demo model is reproducible
./run_qemu.sh                      # boot and exercise your change at the cdk> prompt
```

CI runs the first four on every pull request.

## Security-sensitive changes

Changes to capabilities, cryptography, syscalls, paging, or parsers of
untrusted input (ELF, tokens) need extra care:

- Cryptography stays public and in this repository. Use reviewed
  implementations (RustCrypto) rather than hand-rolled primitives.
- Keep post-quantum usage **hybrid** (classical + PQC; both must verify) and
  record an algorithm identifier in every new format.
- Add negative tests: tampered data, wrong keys, truncated input, and
  out-of-range pointers must all be rejected.
- Never compare secrets or MACs with `==` on slices; use constant-time
  comparison.

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
