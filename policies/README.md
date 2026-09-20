# SOC 2 policy suite (Layer 2)

Rego policies evaluated by Conftest against `terraform show -json` output.
Each carries a `# METADATA` block with `framework: soc2`, `controls`, and the starter `gaps` it detects.

| Policy | SOC 2 | Gap |
|---|---|---|
| `cc6_1_s3_cmk` | CC6.1 | GAP-01 |
| `cc6_1_dynamodb_cmk` | CC6.1 | GAP-02 |
| `cc6_7_s3_tls` | CC6.7 | GAP-03 |
| `a1_2_s3_versioning` | A1.2 | GAP-04 |
| `cc6_6_lambda_vpc` | CC6.6 | GAP-05 |
| `cc7_2_lambda_observability` | CC7.2 | GAP-06 |
| `cc6_3_iam_least_privilege` | CC6.3 | GAP-07 |
| `cc7_2_api_logging` | CC7.2 | GAP-08 |
| `cc7_2_cloudtrail` | CC7.2 | audit trail present |

Policies read the plan's `configuration` section (references), because values such as KMS ARNs are unknown at plan time.
They cover the root module only, and IAM checks require policies built with `aws_iam_policy_document` (`jsonencode` with references is opaque at plan time).

## Fixtures and tests
- `fixtures/pass.json`: plan configuration of the compliant baseline; must produce zero violations.
- `scripts/gap-regression.py`: re-introduces each gap into that fixture and asserts the matching policy fails.

```
python3 scripts/gap-regression.py
scripts/policy-gate.sh --plan terraform/tfplan
```
