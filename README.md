# Acme Health intake - SOC 2 governance wrapper (CGE-P capstone)

Primary framework: **SOC 2 Trust Services Criteria** (CC6.1, CC6.3, CC6.6, CC6.7, CC7.2, A1.2).
The workload is the unmodified-in-purpose patient intake API from `cgep-app-starter` (original README: [docs/STARTER_README.md](docs/STARTER_README.md)).
Design decisions, gap-by-gap results and known limits are in [WRITEUP.md](WRITEUP.md).

| Layer | Where |
|---|---|
| 1. GRC baseline (Terraform) | `terraform/kms.tf`, `evidence_vault.tf`, `cloudtrail.tf`, `workload_hardening.tf`, `monitoring.tf` (Config rules + SNS/EventBridge alerting), in-place edits in `main.tf`; `bootstrap/` (state bucket, GitHub OIDC roles) |
| 2. OPA policies (Rego) | `policies/soc2/` (9 policies), `policies/fixtures/pass.json`, `scripts/gap-regression.py` |
| 3. Pipeline (GitHub Actions) | `.github/workflows/grc-gate.yml`, `scripts/bundle-sign-upload.sh`, `scripts/verify-evidence.sh` |
| 4. OSCAL component | `oscal/components/acme-health-intake.json`, `oscal/profiles/`, `oscal/catalogs/`; regenerate with `scripts/build-oscal.py`, check with `scripts/check-oscal.py` |

## Run it
```
make deploy && make test          # deploy the governed workload (uses the S3 backend from bootstrap/)
python3 scripts/gap-regression.py # each starter gap re-introduced -> policy must fail
python3 scripts/check-oscal.py    # OSCAL traces to real resources, policies and gaps
opa test ./policies               # 24 unit tests, pass + fail fixture per policy
scripts/validate-oscal.sh         # trestle validate (pip install compliance-trestle, Python >= 3.10)
EVIDENCE_VAULT=<vault> scripts/verify-evidence.sh <run_id> plan|apply
make destroy
```
`bootstrap/` is applied once by a human (`cd bootstrap && terraform apply`) before the pipeline can run.

## Proof the gate has teeth
| | Run | Result | Vault evidence |
|---|---|---|---|
| PR #1 (merged) | PR run 35481463190; main push 35481905389; latest main push 35482366069 (30-day retention) | plan, gate, apply passed | `evidence/runs/35482366069/{plan,apply}/` (earlier: `35481905389`) |
| PR #2 (blocked) | 35481966227 | A1.2 policy failed: uploads versioning removed | `evidence/runs/35481966227/plan/` |

All three bundles pass `verify-evidence.sh` (SHA-256, Cosign keyless signature pinned to this repo's workflow, Object Lock retention).
