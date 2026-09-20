# Write-up

## Why SOC 2
Acme Health is a 50-person telehealth company whose near-term goal, per WORKLOAD.md, is a SOC 2 Type II report for enterprise customers. The Trust Services Criteria also fit the technical gaps directly: encryption and access (CC6.x), transmission security (CC6.7), monitoring (CC7.2) and recovery (A1.2). CloudTrail plus the signed, immutable evidence vault produce the operating-effectiveness evidence a Type II audit samples over time. HIPAA is the legal baseline for PHI and is cross-referenced in the starter's GAPS.md, but no policy here uses a HIPAA ID as its primary control.

## Gap results
| Gap | Layer(s) used | Status |
|---|---|---|
| GAP-01 S3 SSE-KMS CMK | Terraform + Rego `cc6_1_s3_cmk` + OSCAL CC6.1 | Closed |
| GAP-02 DynamoDB CMK | Terraform + Rego `cc6_1_dynamodb_cmk` + OSCAL | Closed |
| GAP-03 TLS-only bucket policy | Terraform + Rego `cc6_7_s3_tls` + OSCAL CC6.7 | Closed |
| GAP-04 versioning | Terraform + Rego `a1_2_s3_versioning` + OSCAL A1.2; blocked PR #2 proves the gate | Closed |
| GAP-05 Lambda in VPC | Terraform (private subnets, gateway endpoints, SG) + Rego `cc6_6_lambda_vpc` | Closed |
| GAP-06 concurrency / DLQ / X-Ray | DLQ and X-Ray closed + Rego `cc7_2_lambda_observability` | **Partial**: reserved concurrency not set. The account quota is 10 and AWS requires 10 unreserved. Exposed as `var.lambda_reserved_concurrency`; needs a quota increase. |
| GAP-07 wildcard IAM | Terraform (least privilege) + Rego `cc6_3_iam_least_privilege` | Closed technically; the periodic access review is an organizational control, documented in OSCAL as `partial` |
| GAP-08 API logging / throttling / WAF | Access logs + throttling + Rego `cc7_2_api_logging` | **Partial**: WAFv2 cannot attach to HTTP APIs. |

Additional: `cc7_2_cloudtrail` requires a multi-region, log-validated trail.

## Design decisions
- **Policies read plan `configuration`, not `planned_values`.** Values wired by reference (KMS ARNs, bucket IDs) are unknown at plan time. IAM policies are written with `aws_iam_policy_document` because `jsonencode` over references is opaque to the plan.
- **Regression proof.** `scripts/gap-regression.py` mutates a passing plan fixture to re-introduce each gap and asserts the matching policy fails; it also runs in CI before the gate.
- **Keyless Cosign.** No signing keys to store. The verifier pins the certificate identity to this repo's `grc-pipeline.yml`.
- **Two pipeline roles.** PRs assume a SecurityAudit-based plan role (no PHI reads, evidence-prefix writes only). Only `main` can assume the apply role, which is explicitly denied DynamoDB data-plane access, reads of the uploads bucket, and vault retention bypass. Trust uses GitHub's immutable owner/repo IDs.
- **Bootstrap outside the pipeline.** The state bucket and the roles are applied by a human so the pipeline cannot rewrite its own permissions.

## Known limitations (honest list)
- The apply role has service-level wildcards (`ec2:*`, `kms:*`, `s3:*` ...) needed to create the stack; the denies bound but do not eliminate its power. A production version would use a permissions boundary.
- Bootstrap state is local (`bootstrap/terraform.tfstate`, gitignored) and the bootstrap roles are not covered by the gate.
- Policies cover the root module only and `aws_iam_policy_document`-based IAM.
- No CloudWatch alarms or alert routing exist; monitoring response is an organizational process.
- The vault uses Object Lock **governance** mode with 30-day retention to keep the sandbox destroyable; production evidence should use compliance mode. Evidence from before this change has 1-day retention (objects are not auto-deleted).
- Cosign records signatures in the public Rekor log; for this private repo that exposes the repo name and workflow identity.
- The OSCAL catalog is a self-authored subset with paraphrased titles because AICPA publishes no OSCAL catalog. The `source` URL points at the file in this (private) repo.
- Out of scope, per the starter: API authentication, multi-region failover, patient data lifecycle.
