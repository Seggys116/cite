#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> cargo build -p cite-manager -p cite-executor"
cargo build --locked -p cite-manager -p cite-executor

echo
echo "==> versions"
if [[ -x target/debug/cite-manager ]]; then
  target/debug/cite-manager --version || target/debug/cite-manager version || echo "cite-manager built (no --version yet)"
fi
if [[ -x target/debug/cite ]]; then
  target/debug/cite --version || true
fi
if [[ -x target/debug/cite-executor ]]; then
  target/debug/cite-executor --version || target/debug/cite-executor version || echo "cite-executor built (no --version yet)"
fi

echo
echo "smoke OK"
