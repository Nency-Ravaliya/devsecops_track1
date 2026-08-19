#!/usr/bin/env bash
set -euo pipefail

# Renders Helm charts found under reference-target and runs Conftest (if available)
# Outputs results to ./artifacts/policy-gate/

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/artifacts/policy-gate"
mkdir -p "$OUT_DIR/rendered" "$OUT_DIR/results"

echo "Searching for Helm charts under reference-target..."
charts=()
while IFS= read -r -d '' dir; do
  charts+=("$dir")
done < <(find "$ROOT_DIR/reference-target" -maxdepth 4 -type f -name Chart.yaml -print0 2>/dev/null || true)

if [ ${#charts[@]} -eq 0 ]; then
  echo "No Helm charts found under reference-target. Exiting." >&2
  exit 0
fi

for chartfile in "${charts[@]}"; do
  chartdir=$(dirname "$chartfile")
  chartname=$(basename "$chartdir")
  outfile="$OUT_DIR/rendered/${chartname}.yaml"
  echo "Rendering chart $chartdir -> $outfile"
  helm template "$chartname" "$chartdir" > "$outfile" || echo "helm template failed for $chartdir" >&2
done

echo "Rendered charts saved to $OUT_DIR/rendered"

# Prefer a local conftest binary if present; otherwise try Docker-based conftest
if command -v conftest >/dev/null 2>&1; then
  echo "Found local conftest binary; running tests locally."
  for yf in "$OUT_DIR/rendered"/*.yaml; do
    name=$(basename "$yf")
    echo "Testing $name with local conftest"
    conftest test --policy "$ROOT_DIR/platform-policies/policy" "$yf" > "$OUT_DIR/results/${name}.txt" 2>&1 || true
    echo "Result -> $OUT_DIR/results/${name}.txt"
  done
elif command -v docker >/dev/null 2>&1; then
  echo "Running Conftest (Docker) on each rendered file..."
  for yf in "$OUT_DIR/rendered"/*.yaml; do
    name=$(basename "$yf")
    echo "Testing $name"
    docker run --rm -v "$ROOT_DIR":/workspace -v "$yf":/tmp/rendered.yaml -w /workspace instrumenta/conftest test --policy /workspace/platform-policies/policy /tmp/rendered.yaml > "$OUT_DIR/results/${name}.txt" 2>&1 || true
    echo "Result -> $OUT_DIR/results/${name}.txt"
  done
else
  echo "Neither 'conftest' nor 'docker' found. Please install Conftest (v0.56.0) or Docker to run policy checks."
fi

echo "Policy gate run complete. See $OUT_DIR for artifacts."
