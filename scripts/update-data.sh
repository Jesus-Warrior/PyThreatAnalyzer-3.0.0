#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd "$(dirname "$0")/.." && pwd)"
python "$project_dir/scripts/update-data.py" "$@"
"$project_dir/scripts/check-data-coverage.sh" --strict
