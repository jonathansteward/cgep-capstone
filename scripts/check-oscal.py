#!/usr/bin/env python3
"""Consistency checks for the OSCAL component (offline).
 - every terraform-resource exists in the plan-configuration fixture
 - every rego-policy exists in policies/soc2 with framework: soc2
 - every control-id exists in the catalog subset and in the profile
 - every closes-gap id is covered
 - source names the SOC 2 catalog
"""
import json, os, re, sys

c = json.load(open("oscal/components/acme-health-intake.json"))["component-definition"]
cat = json.load(open("oscal/catalogs/soc2-tsc-catalog.json"))["catalog"]
prof = json.load(open("oscal/profiles/acme-soc2-profile.json"))["profile"]
cfg = json.load(open("policies/fixtures/pass.json"))["configuration"]["root_module"]["resources"]
addrs = {r["address"] for r in cfg}
cat_ids = {ctl["id"] for g in cat["groups"] for ctl in g["controls"]}
prof_ids = set(prof["imports"][0]["include-controls"][0]["with-ids"])

errs, gaps = [], set()
ci = c["components"][0]["control-implementations"][0]
if "soc2" not in ci["source"].lower():
    errs.append("source does not reference the SOC 2 catalog")
for r in ci["implemented-requirements"]:
    cid = r["control-id"]
    if cid not in cat_ids: errs.append(f"{cid} not in catalog")
    if cid not in prof_ids: errs.append(f"{cid} not in profile")
    for p in r["props"]:
        if p["name"] == "terraform-resource" and p["value"] not in addrs:
            errs.append(f"{cid}: unknown terraform resource {p['value']}")
        if p["name"] == "rego-policy":
            f = f"policies/soc2/{p['value']}.rego"
            if not os.path.exists(f): errs.append(f"{cid}: missing {f}")
            elif "framework: soc2" not in open(f).read(): errs.append(f"{f}: framework is not soc2")
        if p["name"] == "closes-gap": gaps.add(p["value"])
    if not any(l["rel"] == "evidence" for l in r["links"]): errs.append(f"{cid}: no evidence link")
want = {f"GAP-0{i}" for i in range(1, 9)}
if want - gaps: errs.append(f"gaps not traced: {sorted(want - gaps)}")
# every policy file is referenced by some requirement
used = {p["value"] for r in ci["implemented-requirements"] for p in r["props"] if p["name"] == "rego-policy"}
for f in os.listdir("policies/soc2"):
    n = f[:-5]
    if f.endswith(".rego") and n != "lib" and n not in used: errs.append(f"policy {n} not referenced in OSCAL")
print("OSCAL check:", "FAIL" if errs else "ok")
for e in errs: print(" -", e)
sys.exit(1 if errs else 0)
