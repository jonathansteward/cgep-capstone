#!/usr/bin/env bash
# scripts/bundle-sign-upload.sh — adapted from cgep Labs 2.5 (capture-evidence) and 4.4 (Cosign + vault upload).
# Bundles an evidence directory with a SHA-256 manifest, signs it keylessly with
# Cosign (GitHub OIDC -> Sigstore), and uploads bundle, signature bundle, digest
# and receipt to the Object Lock vault.
#
#   bundle-sign-upload.sh --dir <evidence dir> --stage <plan|apply> --run-id <id> --vault <bucket>
set -euo pipefail

DIR=""; STAGE=""; RUN_ID=""; VAULT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)    DIR="$2"; shift 2 ;;
    --stage)  STAGE="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --vault)  VAULT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$DIR" || -z "$STAGE" || -z "$RUN_ID" || -z "$VAULT" ]] && { echo "missing args" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"; else SHASUM="shasum -a 256"; fi
SHA="${GITHUB_SHA:-$(git rev-parse HEAD)}"
CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# manifest: per-file digest
{
  echo "["
  FIRST=1
  for f in "$DIR"/*; do
    b=$(basename "$f"); [[ "$b" == "manifest.json" ]] && continue
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    printf '\n  {"filename":"%s","sha256":"%s","size":%s,"captured_at_utc":"%s"}' \
      "$b" "$($SHASUM "$f" | awk '{print $1}')" "$(wc -c < "$f" | tr -d ' ')" "$CAPTURED_AT"
  done
  echo; echo "]"
} > "$DIR/manifest.json"

BUNDLE="evidence-${STAGE}-${RUN_ID}-${SHA}.tar.gz"
tar czf "$BUNDLE" -C "$DIR" .
$SHASUM "$BUNDLE" | awk '{print $1}' > "${BUNDLE}.sha256"
cosign sign-blob --yes --bundle "${BUNDLE}.sig.bundle" "$BUNDLE"

PREFIX="evidence/runs/${RUN_ID}/${STAGE}"
for f in "$BUNDLE" "${BUNDLE}.sha256" "${BUNDLE}.sig.bundle"; do
  aws s3 cp --only-show-errors "$f" "s3://${VAULT}/${PREFIX}/${f}"
done
VERSION_ID=$(aws s3api head-object --bucket "$VAULT" --key "${PREFIX}/${BUNDLE}" --query VersionId --output text)

cat > receipt.json <<JSON
{"run_id":"${RUN_ID}","stage":"${STAGE}","vault":"${VAULT}","bundle_key":"${PREFIX}/${BUNDLE}","version_id":"${VERSION_ID}","sha256":"$(cat "${BUNDLE}.sha256")","commit":"${SHA}","captured_at_utc":"${CAPTURED_AT}"}
JSON
aws s3 cp --only-show-errors receipt.json "s3://${VAULT}/${PREFIX}/receipt.json"
cat receipt.json
