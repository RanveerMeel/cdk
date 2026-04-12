#!/usr/bin/env bash
set -euo pipefail

current_branch="$(git rev-parse --abbrev-ref HEAD)"

if [[ "${current_branch}" == "main" ]]; then
  cat >&2 <<'EOF'
ERROR: direct pushes to 'main' are blocked.

Create a feature branch and push that branch instead:
  git switch -c feat/your-change
  git push -u origin HEAD

Then open a Pull Request into main.
EOF
  exit 1
fi
