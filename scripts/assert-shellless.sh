#!/usr/bin/env bash
# Prove an executor image or container is shell-less: scripts/assert-shellless.sh <image-or-container> | --compose [project]
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "assert-shellless: docker not installed; skipping"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "assert-shellless: docker daemon not running; skipping"
  exit 0
fi

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "usage: $0 <image-or-container> | $0 --compose [project]" >&2
  exit 2
fi

if [[ "$TARGET" == "--compose" ]]; then
  PROJECT="${2:-cite}"
  TARGET="$(docker ps --filter "label=com.docker.compose.project=${PROJECT}" --filter "label=com.docker.compose.service=executor" --format '{{.ID}}' | head -n1 || true)"
  if [[ -z "$TARGET" ]]; then
    echo "assert-shellless: no running executor for project '${PROJECT}'" >&2
    exit 1
  fi
fi

FORBIDDEN=(sh bash busybox apt apt-get curl wget ash dash)

fail() {
  echo "assert-shellless FAIL: $*" >&2
  exit 1
}

if docker exec "$TARGET" sh -c 'true' >/dev/null 2>&1; then
  fail "docker exec … sh succeeded (shell present in $TARGET)"
fi
if docker exec "$TARGET" /bin/sh -c 'true' >/dev/null 2>&1; then
  fail "/bin/sh is executable in $TARGET"
fi
if docker exec "$TARGET" /bin/bash -c 'true' >/dev/null 2>&1; then
  fail "/bin/bash is executable in $TARGET"
fi

inspect_id="$TARGET"
cleanup=""
if docker image inspect "$TARGET" >/dev/null 2>&1 && ! docker container inspect "$TARGET" >/dev/null 2>&1; then
  inspect_id="$(docker create --entrypoint '' "$TARGET" true)"
  cleanup="$inspect_id"
fi

listing="$(mktemp)"
trap 'rm -f "$listing"; [[ -n "$cleanup" ]] && docker rm -f "$cleanup" >/dev/null 2>&1 || true' EXIT
docker export "$inspect_id" | tar -t >"$listing"

for name in "${FORBIDDEN[@]}"; do
  for path in "/bin/$name" "/usr/bin/$name" "/usr/sbin/$name" "/sbin/$name"; do
    if grep -qx ".${path}" "$listing"; then
      if docker cp "${inspect_id}:${path}" /tmp/cite-shellless-probe >/dev/null 2>&1; then
        if [[ -x /tmp/cite-shellless-probe ]]; then
          rm -f /tmp/cite-shellless-probe "$listing"
          fail "forbidden executable present: $path"
        fi
        rm -f /tmp/cite-shellless-probe
      fi
    fi
  done
done
rm -f "$listing"

echo "assert-shellless OK: $TARGET"
