# Write-up

The declared primary framework for this capstone is the **SOC 2 Trust Services Criteria** (Security and Availability: CC6.1, CC6.3, CC6.6, CC6.7, CC7.2, A1.2). Every Rego policy cites a SOC 2 criterion and the OSCAL component's `control-implementation.source` is the SOC 2 catalog in `oscal/catalogs/`.

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

## Continuous monitoring (terraform/monitoring.tf, terraform/logging.tf)
The Conftest gate only catches misconfiguration at plan time, in CI — it says nothing about a change made outside Terraform after deploy (console, CLI, another pipeline). Seven AWS Config managed rules close that gap, each mapped 1:1 to the same gap ID and SOC 2 criterion as a Rego policy (`S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED` → GAP-01/CC6.1, `S3_BUCKET_SSL_REQUESTS_ONLY` → GAP-03/CC6.7, `S3_BUCKET_VERSIONING_ENABLED` → GAP-04/A1.2, `DYNAMODB_TABLE_ENCRYPTED_KMS` → GAP-02/CC6.1, `LAMBDA_INSIDE_VPC` → GAP-05/CC6.6, `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` → GAP-07/CC6.3, `API_GW_EXECUTION_LOGGING_ENABLED` → GAP-08/CC7.2), plus `CLOUD_TRAIL_ENABLED` for the trail itself. An EventBridge rule forwards any rule going `NON_COMPLIANT` to an SNS topic (KMS-encrypted, also used for CloudTrail's own delivery notifications and for S3 event notifications on the uploads/vault/trail buckets). Also added: VPC flow logs to a dedicated CloudWatch log group, a locked-down default security group, CloudTrail's own real-time CloudWatch Logs delivery (alongside the S3 archive), and S3 server access logging + lifecycle rules on the three compliance-relevant buckets.

Two real findings surfaced while deploying this layer, both fixed, both worth recording:
1. **The account's Config recorder existed but had never been started** (`recording: false`). Its `describe-configuration-recorders` output also showed the *default* aws-managed exclusion — `AWS::IAM::Policy/User/Role/Group` are excluded from recording — which was set before this capstone and is outside its scope to change; it means `iam-no-admin` can never get compliance data from this recorder, a genuine account-level limitation, not a rule-authoring gap. Starting the recorder was necessary and low-risk (the existing exclusion scope stands); the other seven rules depend on it.
2. **Two separate `aws_sns_topic_policy` resources pointed at the same SNS topic** (one from the initial Config/CloudTrail wiring, one added for S3 event notifications). SNS topics carry exactly one resource policy, so the two Terraform resources fought over it — each apply's `SetTopicAttributes` call clobbered the other, and destroying the redundant one reset the topic to AWS's default (public) policy. `terraform plan` caught it as unexplained drift after an apply that should have been clean. Fixed by merging every principal (EventBridge, CloudTrail, S3) into the one policy document backing the one `aws_sns_topic_policy` resource; confirmed clean with `terraform plan` showing "No changes" and `aws sns get-topic-attributes` showing all three statements.

As of submission, `aws configservice describe-compliance-by-config-rule` shows:

| Rule | Status |
|---|---|
| `cloudtrail-enabled` | COMPLIANT |
| `s3-sse` | COMPLIANT |
| `s3-tls-only` | COMPLIANT |
| `s3-versioning` | COMPLIANT |
| `dynamodb-cmk` | INSUFFICIENT_DATA (AWS Config's first-time resource discovery for this account, started for this capstone, was still backfilling DynamoDB/Lambda at submission time) |
| `lambda-in-vpc` | INSUFFICIENT_DATA (same) |
| `api-gw-logging` | INSUFFICIENT_DATA (same) |
| `iam-no-admin` | INSUFFICIENT_DATA (structural, not transient — see above; this account's recorder excludes IAM types) |

The rules and alert routing are deployed, correctly scoped (verified via `aws sns get-topic-attributes` and `aws events list-targets-by-rule`, not just by reading the Terraform), and mapped 1:1 to gaps/controls; three are still waiting on AWS's own backfill to report their first result, which is an AWS timing detail, not a defect in this layer.

What wasn't done: no live drift was simulated against running infrastructure the way `gap-regression.py` simulates it against a plan (that would mean deliberately breaking a deployed resource and watching the rule flip and the alert fire), and the SNS topic has no subscriber — wiring an on-call subscription is an organizational step, not a technical one.

## Design decisions
- **Policies read plan `configuration`, not `planned_values`.** Values wired by reference (KMS ARNs, bucket IDs) are unknown at plan time. IAM policies are written with `aws_iam_policy_document` because `jsonencode` over references is opaque to the plan.
- **Regression proof.** `scripts/gap-regression.py` mutates a passing plan fixture to re-introduce each gap and asserts the matching policy fails; it also runs in CI before the gate.
- **Keyless Cosign.** No signing keys to store. The verifier pins the certificate identity to this repo's `grc-gate.yml` (earlier runs were signed under its previous name, `grc-pipeline.yml`; the verifier accepts both).
- **Two pipeline roles.** PRs assume a SecurityAudit-based plan role (no PHI reads, evidence-prefix writes only). Only `main` can assume the apply role, which is explicitly denied DynamoDB data-plane access, reads of the uploads bucket, and vault retention bypass. Trust uses GitHub's immutable owner/repo IDs.
- **Bootstrap outside the pipeline.** The state bucket and the roles are applied by a human so the pipeline cannot rewrite its own permissions.
- **Tier 0 static analysis in CI.** `terraform fmt`/`validate`, `checkov` (config in `.checkov.yaml`, four documented skips — see below), `gitleaks` and `conftest` all run on every PR and push to `main`, not just locally.

## Known limitations (honest list)
- The apply role has service-level wildcards (`ec2:*`, `kms:*`, `s3:*` ...) needed to create the stack; the denies bound but do not eliminate its power. A production version would use a permissions boundary.
- Bootstrap state is local (`bootstrap/terraform.tfstate`, gitignored) and the bootstrap roles are not covered by the gate.
- Policies cover the root module only and `aws_iam_policy_document`-based IAM.
- The SNS topic that AWS Config alerts publish to has no subscriber configured; wiring an on-call subscription is an organizational step (see Continuous monitoring above).
- The vault uses Object Lock **governance** mode with 30-day retention to keep the sandbox destroyable; production evidence should use compliance mode. Evidence from before this change has 1-day retention (objects are not auto-deleted).
- Cosign records signatures in the public Rekor log; for this repo (now public) that exposes the repo name and workflow identity, which was already visible.
- The OSCAL catalog is a self-authored subset with paraphrased titles because AICPA publishes no OSCAL catalog. The `source` URL points at the file in this repo.
- Out of scope, per the starter: API authentication, multi-region failover, patient data lifecycle.
- Four checkov findings are suppressed in `.checkov.yaml`, each with a one-line rationale inline in that file: `CKV_AWS_111/356/109` (a KMS key policy's `Resource` is structurally always `"*"`; least privilege comes from `Principal`, not `Resource`) and `CKV_AWS_309` (the intake API is intentionally unauthenticated — WORKLOAD.md declares API-layer auth out of scope). Inline `#checkov:skip=` HCL comments don't suppress these specific checks in checkov 3.3.10 (they're graph-based, not single-resource checks), which is why the config file exists instead of comments next to each resource.
