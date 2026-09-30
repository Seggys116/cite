#!/usr/bin/env bash
# Inspect a live Cite stack for hardening invariants. Usage: scripts/assert-hardening.sh [compose-project]
set -euo pipefail

PROJECT="${1:-cite}"

if ! command -v docker >/dev/null 2>&1; then
  echo "assert-hardening: docker not installed; skipping"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "assert-hardening: docker daemon not running; skipping"
  exit 0
fi

fail() {
  echo "assert-hardening FAIL: $*" >&2
  exit 1
}

need_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "assert-hardening: jq is required when docker is available" >&2
    exit 1
  fi
}

need_jq

mgr_id="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=manager" --format '{{.ID}}' | head -n1 || true)"
exe_id="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1 || true)"

[[ -n "$mgr_id" ]] || fail "manager container not running for project '${PROJECT}'"
[[ -n "$exe_id" ]] || fail "executor container not running for project '${PROJECT}'"

inspect_one() {
  local id="$1" role="$2"
  local json
  json="$(docker inspect "$id")"

  echo "$json" | jq -e '.[0].HostConfig.Privileged == false' >/dev/null \
    || fail "$role is privileged"

  echo "$json" | jq -e '.[0].HostConfig.ReadonlyRootfs == true' >/dev/null \
    || fail "$role rootfs is not read-only"

  if echo "$json" | jq -r '.[0].Mounts[].Source // empty' | grep -q 'docker.sock'; then
    fail "$role mounts docker.sock"
  fi
  if echo "$json" | jq -r '.[0].HostConfig.Binds[]? // empty' | grep -q 'docker.sock'; then
    fail "$role binds docker.sock"
  fi

  echo "$json" | jq -e '
      (.[0].HostConfig.SecurityOpt // [])
      | map(ascii_downcase)
      | any(startswith("no-new-privileges"))
    ' >/dev/null || fail "$role missing no-new-privileges"

  # Docker reports the dropped capability as ALL or CAP_ALL.
  echo "$json" | jq -e '
      (.[0].HostConfig.CapDrop // [])
      | map(ascii_upcase | sub("^CAP_"; ""))
      | index("ALL") != null
    ' >/dev/null || fail "$role CapDrop does not include ALL"

  echo "$json" | jq -e '
      (.[0].HostConfig.Memory > 0)
      and (.[0].HostConfig.NanoCpus > 0)
      and (.[0].HostConfig.PidsLimit > 0)
    ' >/dev/null || fail "$role has no mem/cpu/pids limit"
}

inspect_one "$mgr_id" manager
inspect_one "$exe_id" executor

mgr_json="$(docker inspect "$mgr_id")"
exe_json="$(docker inspect "$exe_id")"

if echo "$exe_json" | grep -Eq 'CITE_GITHUB_TOKEN|ghp_|github_pat_'; then
  fail "executor inspect output contains the GitHub token"
fi

mgr_caps="$(echo "$mgr_json" | jq -r '.[0].HostConfig.CapAdd // [] | map(ascii_upcase | sub("^CAP_"; "")) | .[]' | sort)"
expected_mgr=$'CHOWN\nDAC_READ_SEARCH\nSETGID\nSETUID'
[[ "$mgr_caps" == "$expected_mgr" ]] || fail "manager CapAdd mismatch (got: $(echo "$mgr_caps" | tr '\n' ' '))"

exe_caps="$(echo "$exe_json" | jq -r '.[0].HostConfig.CapAdd // [] | length')"
[[ "$exe_caps" == "0" ]] || fail "executor CapAdd is not empty"
exe_user="$(echo "$exe_json" | jq -r '.[0].Config.User')"
[[ "$exe_user" == "65532" || "$exe_user" == "65532:65532" || "$exe_user" == "nonroot" ]] \
  || fail "executor user is '$exe_user' (expected 65532)"

mgr_ports="$(echo "$mgr_json" | jq -r '.[0].NetworkSettings.Ports // {} | keys | length')"
[[ "$mgr_ports" == "0" ]] || fail "manager publishes ports"
exe_ports="$(echo "$exe_json" | jq -r '.[0].NetworkSettings.Ports // {} | keys | length')"
[[ "$exe_ports" != "0" ]] || fail "executor publishes no ports"

check_mount_ro() {
  local json="$1" dest="$2" role="$3"
  local ro
  ro="$(echo "$json" | jq -r --arg d "$dest" '. [0].Mounts[] | select(.Destination==$d) | .RW')"
  [[ "$ro" == "false" ]] || fail "$role mount $dest is not read-only"
}

check_mount_rw() {
  local json="$1" dest="$2" role="$3"
  local rw
  rw="$(echo "$json" | jq -r --arg d "$dest" '. [0].Mounts[] | select(.Destination==$d) | .RW')"
  [[ "$rw" == "true" ]] || fail "$role mount $dest is not read-write"
}

check_mount_absent() {
  local json="$1" dest="$2" role="$3"
  if echo "$json" | jq -e --arg d "$dest" '.[0].Mounts[] | select(.Destination==$d)' >/dev/null; then
    fail "$role must not mount $dest"
  fi
}

check_mount_ro "$exe_json" "/var/lib/cite/releases" executor
check_mount_ro "$exe_json" "/var/lib/cite/control" executor
check_mount_rw "$exe_json" "/var/lib/cite/status" executor
check_mount_absent "$exe_json" "/var/lib/cite/state" executor
check_mount_absent "$exe_json" "/var/lib/cite/work" executor
check_mount_absent "$exe_json" "/var/lib/cite/cache" executor

check_mount_rw "$mgr_json" "/var/lib/cite/releases" manager
check_mount_rw "$mgr_json" "/var/lib/cite/control" manager
check_mount_ro "$mgr_json" "/var/lib/cite/status" manager
check_mount_rw "$mgr_json" "/var/lib/cite/state" manager

# Docker Desktop hides the volume mountpoint, so fall back to listing it from a throwaway container.
data_vol="$(echo "$mgr_json" | jq -r '. [0].Mounts[] | select(.Destination=="/var/lib/cite/releases") | .Name')"
[[ -n "$data_vol" ]] || fail "manager releases mount has no volume name"
mountpoint="$(docker volume inspect "$data_vol" --format '{{.Mountpoint}}' 2>/dev/null || true)"
list_cite_data() {
  local sub="$1"
  if [[ -n "$mountpoint" && -r "${mountpoint}${sub}" ]]; then
    find "${mountpoint}${sub}" -mindepth 1 -maxdepth 1 -print
    return
  fi
  docker run --rm --network none -v "${data_vol}:/cite_data:ro" debian:bookworm-slim \
    find "/cite_data${sub}" -mindepth 1 -maxdepth 1 -print
}
top=""
while IFS= read -r entry; do
  [[ -n "$entry" ]] || continue
  base="$(basename "$entry")"
  top="${top} ${base}"
  case "$base" in
    releases|control|status|state) ;;
    *) fail "unexpected path in cite_data: $base" ;;
  esac
done < <(list_cite_data "")
for need in releases control status state; do
  case "$top" in
    *" $need"*|*"$need "*) ;;
    *) fail "cite_data is missing $need" ;;
  esac
done
while IFS= read -r slot; do
  [[ -n "$slot" ]] || continue
  s="$(basename "$slot")"
  case "$s" in
    blue|green) ;;
    *) fail "unexpected releases slot: $s" ;;
  esac
done < <(list_cite_data "/releases")

echo "assert-hardening OK: project=${PROJECT} manager=${mgr_id:0:12} executor=${exe_id:0:12}"
