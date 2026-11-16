#!/usr/bin/env bash
# Download the official Agent Games circuit artifacts into ../circuits/
# (they are kept out of git — run this after cloning / before starting).
set -euo pipefail
mkdir -p "$(dirname "$0")/../circuits"
cd "$(dirname "$0")/../circuits"
BASE="https://agentgames.zkverify.io/circuits"
for f in gatekeeper.wasm gatekeeper_final.zkey vfy-policy.wasm vfy-policy_final.zkey; do
  echo "Downloading $f ..."
  curl -fsSL -o "$f" "$BASE/$f"
done
echo "Done:"
ls -lh
