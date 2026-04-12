#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hook_source="${repo_root}/.githooks/commit-msg"
hook_target="${repo_root}/.git/hooks/commit-msg"

if [[ ! -d "${repo_root}/.git/hooks" ]]; then
  echo "ERROR: .git/hooks directory not found. Run inside a git clone." >&2
  exit 1
fi

cp "$hook_source" "$hook_target"
chmod +x "$hook_target"

echo "Installed commit-msg hook at ${hook_target}"
