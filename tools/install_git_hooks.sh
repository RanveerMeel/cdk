#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
hooks_dir="${repo_root}/.git/hooks"

if [[ ! -d "${hooks_dir}" ]]; then
  echo "ERROR: .git/hooks directory not found. Run inside a git clone." >&2
  exit 1
fi

for hook_name in commit-msg pre-push; do
  hook_source="${repo_root}/.githooks/${hook_name}"
  hook_target="${hooks_dir}/${hook_name}"

  if [[ ! -f "${hook_source}" ]]; then
    echo "ERROR: missing hook source ${hook_source}" >&2
    exit 1
  fi

  cp "${hook_source}" "${hook_target}"
  chmod +x "${hook_target}"
  echo "Installed ${hook_name} hook at ${hook_target}"
done
