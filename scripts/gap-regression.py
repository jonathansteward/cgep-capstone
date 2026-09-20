#!/usr/bin/env python3
"""Re-introduce each starter gap into the passing plan fixture and confirm the
matching SOC 2 policy fails closed. Also confirms the untouched fixture passes.

Usage: python3 scripts/gap-regression.py   (needs conftest on PATH)
"""
import copy, json, subprocess, sys, tempfile, os

FIX = "policies/fixtures/pass.json"
base = json.load(open(FIX))


def res(cfg, addr):
    for r in cfg["configuration"]["root_module"]["resources"]:
        if r["address"] == addr:
            return r
    raise KeyError(addr)


def drop(addr):
    def f(cfg):
        rs = cfg["configuration"]["root_module"]["resources"]
        rs[:] = [r for r in rs if r["address"] != addr]
    return f


def drop_block(addr, key):
    def f(cfg):
        del res(cfg, addr)["expressions"][key]
    return f


def wildcard_iam(cfg):
    res(cfg, "data.aws_iam_policy_document.lambda_inline")["expressions"]["statement"][0]["actions"] = {"constant_value": ["dynamodb:*"]}


# gap id -> (mutation, substring expected in a failure message)
CASES = {
    "GAP-01": (drop("aws_s3_bucket_server_side_encryption_configuration.uploads"), "CC6.1"),
    "GAP-02": (drop_block("aws_dynamodb_table.intake", "server_side_encryption"), "CC6.1"),
    "GAP-03": (drop("aws_s3_bucket_policy.uploads"), "CC6.7"),
    "GAP-04": (drop("aws_s3_bucket_versioning.uploads"), "A1.2"),
    "GAP-05": (drop_block("aws_lambda_function.intake", "vpc_config"), "CC6.6"),
    "GAP-06a": (drop_block("aws_lambda_function.intake", "tracing_config"), "X-Ray"),
    "GAP-06b": (drop_block("aws_lambda_function.intake", "dead_letter_config"), "dead_letter_config"),
    "GAP-07": (wildcard_iam, "CC6.3"),
    "GAP-08a": (drop_block("aws_apigatewayv2_stage.default", "access_log_settings"), "access_log_settings"),
    "GAP-08b": (drop_block("aws_apigatewayv2_stage.default", "default_route_settings"), "throttling"),
    "NO-TRAIL": (drop("aws_cloudtrail.main"), "aws_cloudtrail"),
}


def gate(cfg):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
        json.dump(cfg, t)
    try:
        out = subprocess.run(
            ["conftest", "test", "--policy", "policies/soc2", "--all-namespaces", "--output", "json", t.name],
            capture_output=True, text=True)
    finally:
        os.unlink(t.name)
    return [f["msg"] for r in json.loads(out.stdout) for f in (r.get("failures") or [])]


ok = True
if gate(base):
    print("FAIL  baseline fixture should pass"); ok = False
else:
    print("ok    baseline passes")

for gap, (mutate, expect) in CASES.items():
    cfg = copy.deepcopy(base)
    mutate(cfg)
    fails = gate(cfg)
    hit = any(expect in m for m in fails)
    print(("ok    " if hit else "FAIL  ") + f"{gap}: {len(fails)} violation(s)" + ("" if hit else f" (expected '{expect}')"))
    ok &= hit

sys.exit(0 if ok else 1)
