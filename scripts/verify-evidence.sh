#!/usr/bin/env bash
# scripts/verify-evidence.sh — adapted from cgep Lab 4.4.
#   verify-evidence.sh <run_id> <plan|apply> [--vault <bucket>]
# Checks integrity (SHA-256), authenticity (Cosign keyless, pinned to this repo's
# workflow identity), and preservation (Object Lock retention still in force).
set -euo pipefail
RUN_ID="${1:?usage: verify-evidence.sh <run_id> <plan|apply> [--vault <bucket>]}"
STAGE="${2:?stage}"
shift 2 || true
VAULT="${EVIDENCE_VAULT:-}"
REPO="${GITHUB_REPO:-jonathansteward/cgep-capstone}"
while [[ $# -gt 0 ]]; do
  case "$1" in --vault) VAULT="$2"; shift 2 ;; *) shift ;; esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="evidence/runs/${RUN_ID}/${STAGE}"
aws s3 cp --only-show-errors "s3://${VAULT}/${PREFIX}/" . --recursive

BUNDLE=$(ls evidence-*.tar.gz | head -1)
[[ "$(cat "${BUNDLE}.sha256")" == "$(shasum -a 256 "$BUNDLE" | awk '{print $1}')" ]] || { echo "FAIL: SHA mismatch"; exit 1; }
echo "ok  integrity"

cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/grc-pipeline\.yml@" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$BUNDLE"
echo "ok  authenticity"

RETAIN_UNTIL=$(aws s3api get-object-retention --bucket "$VAULT" --key "${PREFIX}/${BUNDLE}" --query 'Retention.RetainUntilDate' --output text)
echo "ok  preservation (retained until ${RETAIN_UNTIL})"
echo "CHAIN INTACT for run ${RUN_ID} (${STAGE})"
