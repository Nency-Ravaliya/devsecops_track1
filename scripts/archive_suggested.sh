#!/usr/bin/env bash
set -euo pipefail

# Suggest and optionally archive non-essential demo manifests to ./archive/
# Usage: ./archive_suggested.sh [--apply]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_DIR="$ROOT_DIR/archive"

declare -a candidates=(
  "reference-target/infrastructure/helm-tiller/pwnchart"
  "reference-target/scenarios/system-monitor"
  "reference-target/scenarios/health-check"
  "reference-target/scenarios/docker-bench-security"
  "reference-target/scenarios/hunger-check"
)

echo "Candidate files/directories to archive:"
for c in "${candidates[@]}"; do
  if [ -e "$ROOT_DIR/$c" ]; then
    echo " - $c"
  fi
done

if [ "${1-}" = "--apply" ]; then
  mkdir -p "$ARCHIVE_DIR"
  for c in "${candidates[@]}"; do
    if [ -e "$ROOT_DIR/$c" ]; then
      dest="$ARCHIVE_DIR/$(basename "$c")-$(date +%s)"
      echo "Moving $c -> $dest"
      mv "$ROOT_DIR/$c" "$dest"
    fi
  done
  echo "Archive complete. Review $ARCHIVE_DIR before committing." 
else
  echo "Dry-run only. Re-run with --apply to move these files to $ARCHIVE_DIR"
fi
