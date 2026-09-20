#!/usr/bin/env bash
# scripts/policy-gate.sh — adapted from cgep Lab 3.4.
# Runs the SOC 2 Rego suite against a Terraform plan; non-zero exit blocks the merge.
#   scripts/policy-gate.sh --plan terraform/tfplan [--evidence-dir evidence/plan]
set -euo pipefail

POLICY_DIR="policies/soc2"
PLAN=""
EVIDENCE_DIR="evidence/policy-gate"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan)         PLAN="$2"; shift 2 ;;
    --policy)       POLICY_DIR="$2"; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$PLAN" ]] && { echo "Usage: $0 --plan <tfplan or plan.json>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

if [[ "$PLAN" == *.json ]]; then
  cp "$PLAN" "$EVIDENCE_DIR/plan.json"
else
  ( cd "$(dirname "$PLAN")" && terraform show -json "$(basename "$PLAN")" ) > "$EVIDENCE_DIR/plan.json"
fi

set +e
conftest test --policy "$POLICY_DIR" --all-namespaces --output json "$EVIDENCE_DIR/plan.json" > "$EVIDENCE_DIR/conftest-results.json"
RC=$?
set -e

if [[ $RC -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; conftest test --policy "$POLICY_DIR" --all-namespaces "$EVIDENCE_DIR/plan.json" || true
fi
exit $RC
