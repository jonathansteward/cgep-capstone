#!/usr/bin/env bash
# Validate the OSCAL documents with IBM compliance-trestle (needs Python >= 3.10: pip install compliance-trestle).
set -euo pipefail
TRESTLE="${TRESTLE:-trestle}"
SRC="$(cd "$(dirname "$0")/.." && pwd)/oscal"
WS=$(mktemp -d); trap 'rm -rf "$WS"' EXIT
cd "$WS"
"$TRESTLE" init >/dev/null
"$TRESTLE" import -f "$SRC/catalogs/soc2-tsc-catalog.json" -o soc2-tsc >/dev/null
"$TRESTLE" import -f "$SRC/profiles/acme-soc2-profile.json" -o acme-soc2 >/dev/null
"$TRESTLE" import -f "$SRC/components/acme-health-intake.json" -o acme-health-intake >/dev/null
"$TRESTLE" validate -a
