#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <commit-msg-file>" >&2
  exit 2
fi

msg_file="$1"
header="$(sed -n '1p' "$msg_file")"
body="$(sed -n '2,$p' "$msg_file" | tr -d '\r')"

allowed_types="feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert"
header_regex="^(${allowed_types})\\(([a-z0-9]+(-[a-z0-9]+)*)\\)(!)?: [a-z][[:print:]]+$"

if [[ -z "$header" ]]; then
  echo "ERROR: empty commit message header." >&2
  exit 1
fi

if [[ "$header" =~ ^(fixup!|squash!) ]]; then
  echo "ERROR: fixup/squash commits are not allowed." >&2
  exit 1
fi

if [[ "$header" =~ [Ww][Ii][Pp] ]] || [[ "$header" =~ [Tt][Mm][Pp] ]]; then
  echo "ERROR: WIP/tmp commits are not allowed." >&2
  exit 1
fi

if ! [[ "$header" =~ $header_regex ]]; then
  echo "ERROR: commit header must match:" >&2
  echo "  type(scope): short imperative summary" >&2
  echo "Allowed types: feat fix docs style refactor perf test build ci chore revert" >&2
  echo "Scope must be lowercase kebab-case and is required." >&2
  exit 1
fi

header_len="${#header}"
if (( header_len < 15 || header_len > 72 )); then
  echo "ERROR: commit header length must be between 15 and 72 characters." >&2
  exit 1
fi

if [[ "$header" =~ \.$ ]]; then
  echo "ERROR: commit subject must not end with a period." >&2
  exit 1
fi

type="${header%%(*}"
if [[ "$type" == "feat" || "$type" == "fix" || "$type" == "refactor" ]]; then
  trimmed_body="$(printf "%s" "$body" | sed '/^[[:space:]]*$/d')"
  if [[ -z "$trimmed_body" ]]; then
    echo "ERROR: ${type} commits must include a non-empty body with context." >&2
    exit 1
  fi
fi
