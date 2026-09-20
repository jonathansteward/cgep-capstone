#!/usr/bin/env python3
"""Generate the OSCAL catalog subset, profile and component-definition.

Evidence links are built from the vault receipts in oscal/evidence/ so every
href points at a real, signed, Object Lock object (verify with
scripts/verify-evidence.sh). Re-run after new evidence: python3 scripts/build-oscal.py
"""
import json, uuid, datetime, glob, os

NOW = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
REPO = "https://github.com/jonathansteward/cgep-capstone"
CATALOG_URL = f"{REPO}/blob/main/oscal/catalogs/soc2-tsc-catalog.json"
NS = uuid.UUID("6f1c2b7e-3a44-4d43-9a6e-0c5d1f2a9b10")  # stable uuid5 namespace


def u(name):
    return str(uuid.uuid5(NS, name))


# ---- catalog: only the criteria this system claims (titles paraphrased) ----
CONTROLS = {
    "cc6.1": "Logical access security and encryption of protected information assets",
    "cc6.3": "Access authorization based on least privilege",
    "cc6.6": "Boundary protection against threats from outside system boundaries",
    "cc6.7": "Protection of information in transmission",
    "cc7.2": "Monitoring of system components for anomalies and security events",
    "a1.2": "Environmental protections, backup and recovery infrastructure",
}
catalog = {"catalog": {
    "uuid": u("catalog"),
    "metadata": {
        "title": "SOC 2 Trust Services Criteria (2017, rev. 2022) - criteria claimed by Acme Health intake",
        "last-modified": NOW, "version": "1.0.0", "oscal-version": "1.2.1",
        "remarks": "AICPA publishes no official OSCAL catalog. This is a subset limited to the criteria "
                   "referenced by this capstone; titles are paraphrased, not the AICPA text.",
    },
    "groups": [{"id": "soc2", "title": "Trust Services Criteria", "controls": [
        {"id": cid, "title": t, "props": [{"name": "label", "value": cid.upper()}]}
        for cid, t in CONTROLS.items()]}],
}}

profile = {"profile": {
    "uuid": u("profile"),
    "metadata": {"title": "Acme Health intake - SOC 2 profile", "last-modified": NOW,
                 "version": "1.0.0", "oscal-version": "1.2.1"},
    "imports": [{"href": "../catalogs/soc2-tsc-catalog.json",
                 "include-controls": [{"with-ids": list(CONTROLS)}]}],
    "merge": {"as-is": True},
}}

# ---- evidence from receipts ----
rec = {}
for f in sorted(glob.glob("oscal/evidence/receipt-*.json")):
    r = json.load(open(f))
    rec[(r["run_id"], r["stage"])] = r
MAIN_RUN, BLOCKED_RUN = "35482366069", "35481966227"


def evidence_links(*keys):
    out = []
    for k in keys:
        r = rec[k]
        label = {"plan": "signed plan + policy-gate results", "apply": "signed post-apply state summary"}[r["stage"]]
        out.append({
            "rel": "evidence",
            "href": f"s3://{r['vault']}/{r['bundle_key']}?versionId={r['version_id']}",
            "text": f"Run {r['run_id']} ({'merged to main' if r['run_id']==MAIN_RUN else 'PR blocked by gate'}): {label}; "
                    f"sha256 {r['sha256']}; Cosign keyless bundle alongside as .sig.bundle. "
                    f"Check: scripts/verify-evidence.sh {r['run_id']} {r['stage']}",
        })
    return out


MAIN = evidence_links((MAIN_RUN, "plan"), (MAIN_RUN, "apply"))
BLOCKED = evidence_links((BLOCKED_RUN, "plan"))


def req(cid, desc, resources, policies, gaps, status, evidence, remarks=None, extra_links=()):
    props = [{"name": "implementation-status", "value": status}]
    props += [{"name": "terraform-resource", "value": r} for r in resources]
    props += [{"name": "rego-policy", "value": p} for p in policies]
    props += [{"name": "closes-gap", "value": g} for g in gaps]
    d = {"uuid": u("req-" + cid), "control-id": cid, "description": desc, "props": props,
         "links": evidence + list(extra_links)}
    if remarks:
        d["remarks"] = remarks
    return d


POL = lambda n: {"rel": "reference", "href": f"../../policies/soc2/{n}.rego", "text": f"Rego policy {n}"}

reqs = [
    req("cc6.1",
        "PHI at rest is encrypted with customer-managed, annually rotated KMS keys: the uploads bucket (SSE-KMS), "
        "the DynamoDB submissions table, the evidence vault, the CloudTrail bucket, the DLQ and API access logs.",
        ["aws_kms_key.data", "aws_kms_key.evidence_key", "aws_s3_bucket_server_side_encryption_configuration.uploads",
         "aws_dynamodb_table.intake", "aws_s3_bucket_server_side_encryption_configuration.vault",
         "aws_s3_bucket_server_side_encryption_configuration.trail", "aws_sqs_queue.dlq",
         "aws_cloudwatch_log_group.api_access"],
        ["cc6_1_s3_cmk", "cc6_1_dynamodb_cmk"], ["GAP-01", "GAP-02"], "implemented", MAIN,
        extra_links=[POL("cc6_1_s3_cmk"), POL("cc6_1_dynamodb_cmk")]),
    req("cc6.3",
        "The intake Lambda role is limited to dynamodb:PutItem on the table, s3:PutObject on the uploads bucket, "
        "data-key use and SQS send; wildcard actions are blocked by policy. Pipeline roles are split: a metadata-only "
        "plan role for pull requests and an apply role for main that is denied PHI data-plane access and vault tampering.",
        ["data.aws_iam_policy_document.lambda_inline", "aws_iam_role_policy.lambda_inline", "aws_iam_role.lambda"],
        ["cc6_3_iam_least_privilege"], ["GAP-07"], "partial", MAIN,
        remarks="Technical least privilege is implemented and gated. The periodic (at least annual) human access "
                "review that CC6.3 also expects is an organizational process that Terraform cannot enforce; it is "
                "owned by the Acme security lead and is not evidenced in this repository.",
        extra_links=[POL("cc6_3_iam_least_privilege"), {"rel": "reference", "href": "../../bootstrap/main.tf", "text": "Pipeline roles cgep-capstone-gh-plan / gh-apply (bootstrap, not gated by this pipeline)."}]),
    req("cc6.6",
        "The Lambda runs in the VPC private subnets with a security group that allows egress only to the S3 and "
        "DynamoDB gateway endpoints; private subnets have no internet route.",
        ["aws_lambda_function.intake", "aws_security_group.lambda", "aws_vpc_endpoint.s3", "aws_vpc_endpoint.dynamodb",
         "aws_route_table.private", "aws_vpc_security_group_egress_rule.lambda_s3",
         "aws_vpc_security_group_egress_rule.lambda_dynamodb"],
        ["cc6_6_lambda_vpc"], ["GAP-05"], "implemented", MAIN,
        remarks="The API Gateway HTTP API remains the public entry point by design; WAFv2 cannot be associated with HTTP APIs.",
        extra_links=[POL("cc6_6_lambda_vpc")]),
    req("cc6.7",
        "Every S3 bucket carries a bucket policy denying requests where aws:SecureTransport is false; the API "
        "endpoint is HTTPS-only.",
        ["aws_s3_bucket_policy.uploads", "data.aws_iam_policy_document.uploads_tls", "aws_s3_bucket_policy.vault",
         "aws_s3_bucket_policy.trail", "aws_apigatewayv2_api.intake"],
        ["cc6_7_s3_tls"], ["GAP-03"], "implemented", MAIN + BLOCKED[:0],
        extra_links=[POL("cc6_7_s3_tls")]),
    req("cc7.2",
        "Activity is recorded and anomalies are surfaced: a multi-region KMS-encrypted CloudTrail with log-file "
        "validation, API Gateway access logs (365-day retention) with throttling, Lambda X-Ray tracing and a "
        "dead-letter queue, and signed evidence written to an Object Lock vault on every pipeline run.",
        ["aws_cloudtrail.main", "aws_apigatewayv2_stage.default", "aws_cloudwatch_log_group.api_access",
         "aws_lambda_function.intake", "aws_sqs_queue.dlq", "aws_s3_bucket_object_lock_configuration.vault"],
        ["cc7_2_cloudtrail", "cc7_2_api_logging", "cc7_2_lambda_observability"], ["GAP-06", "GAP-08"], "partial",
        MAIN + BLOCKED,
        remarks="Not closed: (1) Lambda reserved concurrency, because the account concurrency quota is 10 and AWS "
                "requires 10 unreserved; it is exposed as var.lambda_reserved_concurrency. (2) WAF, which is not "
                "supported on HTTP APIs. (3) No alarms or alert routing are defined; detection rules and on-call "
                "response are an organizational process. The blocked PR run shows the gate refusing a regression.",
        extra_links=[POL("cc7_2_cloudtrail"), POL("cc7_2_api_logging"), POL("cc7_2_lambda_observability")]),
    req("a1.2",
        "S3 versioning is enabled on the uploads bucket, DynamoDB point-in-time recovery is on, and the evidence "
        "vault is versioned with Object Lock.",
        ["aws_s3_bucket_versioning.uploads", "aws_dynamodb_table.intake", "aws_s3_bucket_versioning.vault",
         "aws_s3_bucket_object_lock_configuration.vault"],
        ["a1_2_s3_versioning"], ["GAP-04"], "implemented", MAIN + BLOCKED,
        remarks="The blocked PR (run %s) removed uploads versioning and was rejected by the A1.2 policy." % BLOCKED_RUN,
        extra_links=[POL("a1_2_s3_versioning")]),
]

party = u("party")
component = {"component-definition": {
    "uuid": u("component-definition"),
    "metadata": {"title": "Acme Health patient intake API - SOC 2 component definition", "last-modified": NOW,
                 "version": "1.0.0", "oscal-version": "1.2.1",
                 "parties": [{"uuid": party, "type": "person", "name": "Jonathan Steward"}]},
    "components": [{
        "uuid": u("component"), "type": "software", "title": "acme-health-intake",
        "description": "AWS patient intake workload (API Gateway HTTP API, Lambda, DynamoDB, S3) wrapped with a "
                       "KMS/vault/CloudTrail baseline, an OPA policy gate and a signed-evidence pipeline.",
        "purpose": "Collect patient intake submissions (PHI) under SOC 2 Security and Availability criteria.",
        "responsible-roles": [{"role-id": "provider", "party-uuids": [party]}],
        "control-implementations": [{
            "uuid": u("control-implementation"),
            "source": CATALOG_URL,
            "description": "SOC 2 Trust Services Criteria satisfied by the Terraform in terraform/ and enforced by policies/soc2/.",
            "props": [{"name": "framework", "value": "soc2"},
                      {"name": "profile", "value": "oscal/profiles/acme-soc2-profile.json"}],
            "implemented-requirements": reqs,
        }],
    }],
}}

for path, doc in [("oscal/catalogs/soc2-tsc-catalog.json", catalog),
                  ("oscal/profiles/acme-soc2-profile.json", profile),
                  ("oscal/components/acme-health-intake.json", component)]:
    json.dump(doc, open(path, "w"), indent=2)
    print("wrote", path)
