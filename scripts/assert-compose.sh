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

# The node overlay mounts the Docker socket into the proxy on purpose, so it has its own checks: the backup volume has a
# fixed name the proxy and the connector agree on, the connector mounts it, and data services are wired on both sides.
check_node_overlay() {
  local rendered
  rendered="$(DOCKER_GID=999 CITE_CONNECTOR_ALLOW=127.0.0.1 CITE_CONNECTOR_BIND=127.0.0.1 \
    docker compose -f docker-compose.node.yml -f docker-compose.orchestrator.yml config 2>/dev/null)" ||
    fail "docker compose node + orchestrator config failed"

  echo "$rendered" | awk '
    $0 ~ /^volumes:/ {top=1; next}
    top && $0 ~ /^  cite_backups:/ {seen=1; next}
    top && seen && $0 ~ /^    name: cite-backups$/ {named=1}
    top && $0 ~ /^[a-z]/ {top=0}
    END { exit named ? 0 : 1 }
  ' || fail "orchestrator overlay: the cite_backups volume must be named cite-backups"

  echo "$rendered" | grep -Eq 'target: /backups$' || fail "orchestrator overlay: the connector does not mount /backups"
  echo "$rendered" | grep -Eq 'source: cite_backups$' || fail "orchestrator overlay: the connector mounts no cite_backups volume"
  for want in CITE_DATA_BACKUP_DIR CITE_DATA_BACKUP_VOLUME CITE_DATA_S3_ALLOW_PRIVATE CITE_DATA_JOB_TIMEOUT \
    CITE_SECRETS_KEY_FILE CITE_PROXY_BACKUP_VOLUME CITE_PROXY_DATA; do
    echo "$rendered" | grep -q "$want:" || fail "orchestrator overlay: $want is not set"
  done
  echo "$rendered" | grep -Eq 'CITE_DATA_BACKUP_VOLUME: cite-backups$' || fail "orchestrator overlay: connector and proxy disagree on the backup volume"
  echo "$rendered" | grep -Eq 'CITE_PROXY_BACKUP_VOLUME: cite-backups$' || fail "orchestrator overlay: connector and proxy disagree on the backup volume"
  echo "assert-compose OK: node overlay"
}

check_file docker-compose.yml
check_file docker-compose.dev.yml
check_node_overlay

echo "assert-compose OK: all files"
