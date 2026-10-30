#!/usr/bin/env python3
"""Run applygate plan-check on every plan the study generated, in both tiers.

    evaluate.py APPLYGATE_BIN OUTDIR

Reads work/out/<repo>__<root>/{create,noop,tags,destroy}.json and status.txt,
runs `APPLYGATE_BIN plan-check --tier T` for T in protected and standard from
an empty directory with an empty user config (built-in defaults: protected
max_destroy 0, no scope, no protected_resources), and writes:

  OUTDIR/verdicts.jsonl  one line per plan and tier: verdict, the findings
                         that set it, and the plan's action counts
  OUTDIR/roots.jsonl     one line per root: mode, which steps ran, and why a
                         root produced no plan

Reads plan JSON and runs plan-check only; never runs Terraform.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
KINDS = ("create", "noop", "tags", "destroy")
TIERS = ("protected", "standard")
RANK = {"allow": 0, "ask": 1, "block": 2}


def finding_verdict(sev, tier):
    """Mirror of policy.FindingVerdict."""
    if tier == "protected":
        return {"critical": "block", "high": "ask"}.get(sev, "allow")
    return "ask" if sev == "critical" else "allow"


def parse(text):
    lines = text.splitlines()
    m = re.match(r"tier (\w+): (\w+) \((\d+) changes, (\d+) deletes, (\d+) replaces\)", lines[0])
    head = dict(verdict=m.group(2), changes=int(m.group(3)), deletes=int(m.group(4)), replaces=int(m.group(5)))
    findings, cur = [], None
    for ln in lines[1:]:
        f = re.match(r"- (\w+) ([\w-]+): (.*)", ln)
        if f:
            cur = dict(severity=f.group(1), rule=f.group(2), message=f.group(3), evidence=[])
            findings.append(cur)
        elif ln.startswith("    ") and cur:
            cur["evidence"].append(ln.strip())
    head["findings"] = findings
    return head


def actions(plan):
    """Action counts, plus the addresses the review needs: what is replaced
    (with Terraform's reason), deleted and created, and which data sources
    are read at apply time (a deferred read: an external data source then
    runs during the apply, not only during the plan)."""
    c = {"create": 0, "update": 0, "delete": 0, "replace": 0}
    replaced, deleted, created, apply_reads = [], [], [], []
    for rc in plan.get("resource_changes") or []:
        if rc.get("mode") == "data":
            if "read" in rc["change"]["actions"]:
                apply_reads.append(rc["address"])
            continue
        a = rc["change"]["actions"]
        if a in (["no-op"], ["read"]):
            continue
        if len(a) == 2:
            c["replace"] += 1
            replaced.append({"address": rc["address"], "type": rc["type"],
                             "replace_paths": rc["change"].get("replace_paths"),
                             "reason": rc.get("action_reason")})
        elif a == ["delete"]:
            c["delete"] += 1
            deleted.append(rc["address"])
        elif a[0] in c:
            c[a[0]] += 1
            if a == ["create"]:
                created.append(rc["address"])
    return c, replaced, deleted, created, apply_reads


def status(d):
    st = {}
    p = os.path.join(d, "status.txt")
    if os.path.exists(p):
        for ln in open(p):
            k, _, v = ln.rstrip("\n").partition("=")
            st[k] = v  # a retried step keeps its last exit code
    return st


def why_no_plan(d, st):
    """First error line of the step that failed, for roots without a create plan."""
    for step in ("get", "init", "create"):
        if st.get(step) not in (None, "0"):
            log = os.path.join(d, step + ".log")
            text = open(log, errors="replace").read() if os.path.exists(log) else ""
            m = re.search(r"Error: (.*)", text)
            return step, (m.group(1).strip() if m else "exit " + st[step])
    return None, None


def main():
    binary, outdir = os.path.abspath(sys.argv[1]), sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    src = os.path.join(HERE, "work", "out")
    cwd = tempfile.mkdtemp(prefix="fp-eval-cwd-")
    env = dict(os.environ, XDG_CONFIG_HOME=tempfile.mkdtemp(prefix="fp-eval-xdg-"))
    with open(os.path.join(outdir, "verdicts.jsonl"), "w") as vout, open(os.path.join(outdir, "roots.jsonl"), "w") as rout:
        for slug in sorted(os.listdir(src)):
            d = os.path.join(src, slug)
            st = status(d)
            step, err = why_no_plan(d, st)
            kinds = [k for k in KINDS if os.path.exists(os.path.join(d, k + ".json")) and st.get(k + "-show") == "0"]
            rout.write(json.dumps({"slug": slug, "repo": st.get("repo"), "root": st.get("root"), "mode": st.get("mode"),
                                   "partial": st.get("partial") == "1", "steps": st, "plans": kinds, "failed_step": step, "error": err}) + "\n")
            for kind in kinds:
                pj = os.path.join(d, kind + ".json")
                plan = json.load(open(pj))
                counts, replaced, deleted, created, apply_reads = actions(plan)
                for tier in TIERS:
                    r = subprocess.run([binary, "plan-check", "--tier", tier, "--cwd", cwd, pj],
                                       capture_output=True, text=True, env=env, cwd=cwd)
                    if r.returncode not in (0, 3, 4):
                        raise SystemExit(f"{slug}/{kind}/{tier}: plan-check exit {r.returncode}: {r.stderr}")
                    res = parse(r.stdout)
                    drivers = [f["rule"] for f in res["findings"] if finding_verdict(f["severity"], tier) == res["verdict"] and res["verdict"] != "allow"]
                    if res["deletes"] and res["verdict"] == ("block" if tier == "protected" else "ask"):
                        drivers.append("deletes")
                    vout.write(json.dumps({"slug": slug, "repo": st.get("repo"), "root": st.get("root"), "kind": kind, "tier": tier,
                                           "partial": st.get("partial") == "1", "verdict": res["verdict"], "exit": r.returncode, "drivers": sorted(set(drivers)),
                                           "findings": res["findings"], "counts": counts, "replaced": replaced, "deleted": deleted,
                                           "created": created, "apply_reads": apply_reads}) + "\n")
    print("wrote", os.path.join(outdir, "verdicts.jsonl"), "and roots.jsonl")


if __name__ == "__main__":
    main()
