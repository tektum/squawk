#!/bin/bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/src/generated"
cd "$root/matcher"
GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -o "$root/src/generated/osv_matcher.wasm" .
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$root/src/generated/wasm_exec.js"
