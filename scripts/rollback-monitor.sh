#!/bin/bash
set -euo pipefail
verity_dir=${1:-../verity-images-squawk}
baseline=3163fae8bd874840cab5f6ad668bc92db3a659c7
git -C "$verity_dir" show "$baseline:.github/workflows/monitor.yaml" > "$verity_dir/.github/workflows/monitor.yaml"
git -C "$verity_dir" show "$baseline:scripts/monitor_sboms.sh" > "$verity_dir/scripts/monitor_sboms.sh"
