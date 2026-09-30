#!/usr/bin/env bash
# Structural checks against rendered Compose config; needs `docker compose config` only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "assert-compose FAIL: $*" >&2
  exit 1
}

if ! command -v docker >/dev/null 2>&1; then
  echo "assert-compose: docker not installed; skipping"
  exit 0
fi

export CITE_REPO="${CITE_REPO:-owner/repo}"
export CITE_GITHUB_TOKEN="${CITE_GITHUB_TOKEN:-dummy-token-for-config-render}"

check_file() {
  local file="$1"
  local rendered
  rendered="$(docker compose -f "$file" config 2>/dev/null)" || fail "docker compose -f $file config failed"

  if echo "$rendered" | awk '
    $0 ~ /^  manager:/ {in_mgr=1; next}
    $0 ~ /^  [a-z]/ {in_mgr=0}
    in_mgr && $0 ~ /^    ports:/ {found=1}
    END { exit found ? 0 : 1 }
  '; then
    fail "$file: manager service publishes a port"
  fi

  echo "$rendered" | grep -qi 'docker.sock' && fail "$file: docker.sock appears in config"
  echo "$rendered" | grep -Eiq 'privileged:[[:space:]]*true' && fail "$file: privileged: true appears"
  echo "$rendered" | grep -A2 'depends_on:' | grep -Ev 'depends_on:|init:|condition: service_completed_successfully|^--$' | grep -q . && fail "$file: services may depend only on init"
  echo "$rendered" | grep -q 'max-size: 10m' || fail "$file: missing log max-size 10m"
  echo "$rendered" | grep -Eq 'max-file: "?3"?' || fail "$file: missing log max-file 3"
  echo "$rendered" | grep -q 'healthcheck:' || fail "$file: missing healthcheck"

  if ! echo "$rendered" | awk '
    $0 ~ /^  executor:/ {in_exe=1; next}
    $0 ~ /^  [a-z]/ {in_exe=0}
    in_exe && $0 ~ /^    ports:/ {found=1}
    END { exit found ? 0 : 1 }
  '; then
    fail "$file: executor service does not publish a port"
  fi

  echo "assert-compose OK: $file"
}

if grep -Eq 'ghp_|github_pat_|CITE_GITHUB_TOKEN=[^[:space:]]' .env.example; then
  fail ".env.example contains a secret"
fi

check_file docker-compose.yml
check_file docker-compose.dev.yml

echo "assert-compose OK: all files"
