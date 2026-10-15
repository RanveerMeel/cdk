#!/usr/bin/env bash
# pre-push check: refuse any push that would update the remote 'main'.
# Git passes one "<local ref> <local sha> <remote ref> <remote sha>" line per
# ref being pushed on stdin; only a remote ref of refs/heads/main is blocked, so
# tags and feature branches can be pushed from any checkout (including main).
set -euo pipefail

blocked=0
while read -r _local_ref _local_sha remote_ref _remote_sha; do
  if [[ "${remote_ref}" == "refs/heads/main" ]]; then
    blocked=1
  fi
done

if [[ "${blocked}" == 1 ]]; then
  cat >&2 <<'EOF'
ERROR: direct pushes to 'main' are blocked.

Create a feature branch and push that branch instead:
  git switch -c feat/your-change
  git push -u origin HEAD

Then open a Pull Request into main.
EOF
  exit 1
fi
