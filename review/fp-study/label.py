#!/usr/bin/env python3
"""Label every prompt of the false-positive study and write the summary.

    label.py RESULTS_DIR

Reads RESULTS_DIR/verdicts.jsonl and roots.jsonl (evaluate.py), labels every
ask and block after hand review, and writes RESULTS_DIR/labels.jsonl and
RESULTS_DIR/summary.md.

Routine plans are create, noop and tags; a prompt on one is reviewed and
labelled. The destroy plan is the control and should prompt whenever it
deletes something.

Labels, as in the static trial (review/oss-corpus/tools/label.py):
  expected        the plan does what the rule exists to catch, and prompting
                  in that tier is the policy working
  fp-analyzer     the rule fired on something the plan does not do
  fp-policy       the rule read the plan right, but the policy should not
                  prompt for it in that tier
  fp-environment  caused by LocalStack, not by the configuration
  debatable       a reasonable team could go either way
The rules below encode the review decisions; each names what it covers so the
labels can be checked against the evidence in labels.jsonl.
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

ROUTINE = ("create", "noop", "tags")

ADMIN_ATTACH = ": attaches "
INTERNET = ": ingress from the internet on "
WILDCARD = ": IAM policy allows wildcard action "


def config_addr(a):
    """Strip instance keys: module.x["a"].null_resource.archive[0] -> module.x.null_resource.archive."""
    return re.sub(r"\[[^\]]*\]", "", a)


def code_execution(r, f, ctx):
    """A provisioner runs on apply only when its resource is created or
    replaced; an external data source runs on apply only when its read was
    deferred to apply (otherwise it already ran during the plan)."""
    created = {config_addr(a) for a in r["created"]}
    changing = created | {config_addr(x["address"]) for x in r["replaced"]}
    tainted = {config_addr(x["address"]) for x in r["replaced"] if x.get("reason") == "replace_because_tainted"}
    reads = {config_addr(a) for a in r["apply_reads"]}
    # On a day-2 plan over a partial apply, creates are what never applied,
    # and an external read is deferred to apply only because it waits on them.
    leftover = r["kind"] in ("noop", "tags") and r["partial"]
    real, by_env = [], []
    for e in f["evidence"]:
        addr = config_addr(e.split(": ", 1)[0])
        if ": provisioner " in e and addr in changing:
            (by_env if addr in tainted or (leftover and addr in created) else real).append(e)
        elif "external data source" in e and addr in reads:
            (by_env if leftover else real).append(e)
    if real:
        return "expected", "applying the plan runs code with the user's credentials (a provisioner on a resource being created, or an external data source read at apply); spec S12"
    if by_env:
        return "fp-environment", "the code that runs belongs to a resource replaced because its create failed in LocalStack or the container (tainted), or re-planned after a partial apply"
    return "fp-analyzer", "flags provisioners whose resource is neither created nor replaced, and external data sources already read during the plan; applying this plan runs none of them"


def destroy_count(r, f, ctx):
    noop = ctx.get((r["slug"], "noop", r["tier"]))
    reasons = {x.get("reason") for x in r["replaced"]}
    if r["kind"] == "noop" and not r["deleted"]:
        return "fp-environment", "replaces in a no-op re-plan: resources tainted by a create that failed in LocalStack, or attributes LocalStack reads back differently (replace_because_cannot_update)"
    if r["kind"] == "tags" and noop and not r["deleted"] and \
            {x["address"] for x in r["replaced"]} <= {x["address"] for x in noop["replaced"]}:
        return "fp-environment", "the same replaces as the no-op re-plan (LocalStack drift or tainted resources), not caused by the tag change"
    if r["kind"] == "create" and not r["replaced"] and not r["deleted"]:
        return "fp-analyzer", "create plan with nothing destroyed"
    return "unreviewed", "routine plan destroys or replaces resources: " + ", ".join(sorted(reasons, key=str))


def exposure(r, f, ctx):
    ev = f["evidence"]
    updated = r["kind"] in ("noop", "tags")
    if updated:
        return "fp-analyzer", "re-flags an exposure the plan does not change: the resource is updated only for its tags, and the rule reads the planned value without comparing it with the prior one"
    if all(ADMIN_ATTACH in e or INTERNET in e for e in ev):
        return "expected", "create attaches an AWS-managed admin policy or opens a port range to the internet; asking in a protected tier is the rule's purpose"
    if all(WILDCARD in e for e in ev):
        acts = sorted({e.split(WILDCARD, 1)[1] for e in ev})
        return "debatable", "create grants a service wildcard (" + ", ".join(acts) + "); the rule treats every service:* alike, including low-risk telemetry services"
    return "unreviewed", "mixed exposure evidence"


def stateful_unprotected_create(r, f, ctx):
    if r["kind"] == "create":
        return "expected", "creates a database with deletion protection off and the final snapshot skipped (the examples are written for easy teardown); asking in a protected tier is the rule's purpose"
    return "unreviewed", "stateful-unprotected-create on a day-2 plan"


REVIEW = {"code-execution": code_execution, "destroy-count": destroy_count, "exposure": exposure,
          "stateful-unprotected-create": stateful_unprotected_create}


def label_finding(r, f, ctx):
    fn = REVIEW.get(f["rule"])
    if fn:
        return fn(r, f, ctx)
    return "unreviewed", "no review rule for " + f["rule"] + "; review by hand and add one"


def label(r, ctx):
    """Label a routine prompt. Each driving rule is labelled; the prompt is
    justified if any driver is (expected, then debatable), a false positive
    if none is, and environment-only if every driver is fp-environment."""
    parts = []
    for rule in r["drivers"]:
        if rule == "deletes":
            parts.append(("unreviewed", "routine plan deletes resources", rule))
            continue
        f = next(x for x in r["findings"] if x["rule"] == rule)
        lab, why = label_finding(r, f, ctx)
        parts.append((lab, why, rule))
    order = ["unreviewed", "expected", "debatable", "fp-analyzer", "fp-policy", "fp-environment"]
    parts.sort(key=lambda p: order.index(p[0]))
    return parts[0][0], parts


def pct(n, d):
    return f"{100 * n / d:.1f}%" if d else "n/a"


def main():
    d = sys.argv[1]
    rows = [json.loads(l) for l in open(os.path.join(d, "verdicts.jsonl"))]
    roots = [json.loads(l) for l in open(os.path.join(d, "roots.jsonl"))]
    ctx = {(r["slug"], r["kind"], r["tier"]): r for r in rows}
    out = []
    for r in rows:
        if r["kind"] in ROUTINE and r["verdict"] != "allow":
            r["label"], parts = label(r, ctx)
            r["review"] = [{"rule": p[2], "label": p[0], "why": p[1]} for p in parts]
        else:
            r["label"] = r["verdict"] if r["kind"] in ROUTINE else "control"
        out.append(r)
    with open(os.path.join(d, "labels.jsonl"), "w") as fh:
        for r in out:
            fh.write(json.dumps(r) + "\n")
    write_summary(d, out, roots)


def write_summary(d, rows, roots):
    L = []
    w = L.append
    meta = open(os.path.join(d, "meta.txt")).read() if os.path.exists(os.path.join(d, "meta.txt")) else ""
    w("# False-positive study on real plans: summary\n")
    if meta:
        w("```\n" + meta.strip() + "\n```\n")
    w("Method: [README.md](../../README.md). A prompt is an ask or a block from "
      "`applygate plan-check` with built-in defaults. Routine plans are the first "
      "create, a no-op re-plan and a provider default-tag change; the destroy plan is "
      "the control. Labels are the hand review encoded in [label.py](../../label.py).\n")

    # Coverage
    by_repo = defaultdict(lambda: Counter())
    for rt in roots:
        c = by_repo[rt["repo"]]
        c["roots"] += 1
        c["planned"] += "create" in rt["plans"]
        c["day2"] += "tags" in rt["plans"]
        c["partial"] += bool(rt.get("partial")) and "tags" in rt["plans"]
    w("## Coverage\n")
    w("| Repository | Mode | Roots | Create plan | Day-2 plans (no-op, tags) | of which over a partial apply |")
    w("|---|---|---|---|---|---|")
    modes = {rt["repo"]: rt["mode"] for rt in roots}
    tot = Counter()
    for repo in sorted(by_repo):
        c = by_repo[repo]
        tot.update(c)
        w(f"| {repo} | {modes[repo]} | {c['roots']} | {c['planned']} | {c['day2']} | {c['partial']} |")
    w(f"| **all** | | **{tot['roots']}** | **{tot['planned']}** | **{tot['day2']}** | **{tot['partial']}** |\n")

    # Headline
    w("## Routine plans that prompted\n")
    w("\"Prompted\" is what this run measured. \"Environment-only\" prompts were caused "
      "entirely by LocalStack or the container (tainted creates, attributes read back "
      "differently) and would not occur against AWS; \"Outside LocalStack\" removes them. "
      "\"False positives\" are prompts that no driving rule justifies (fp-analyzer, "
      "fp-policy); \"debatable\" ones are counted separately.\n")
    w("| Plan | Tier | Plans | Prompted | Environment-only | Outside LocalStack | Rate | Expected | Debatable | False positives | FP rate |")
    w("|---|---|---|---|---|---|---|---|---|---|---|")
    for tier in ("protected", "standard"):
        for kind in ROUTINE + ("all routine",):
            sel = [r for r in rows if r["tier"] == tier and (r["kind"] == kind or (kind == "all routine" and r["kind"] in ROUTINE))]
            p = [r for r in sel if r["verdict"] != "allow"]
            env = [r for r in p if r["label"] == "fp-environment"]
            real = [r for r in p if r["label"] != "fp-environment"]
            exp = [r for r in real if r["label"] == "expected"]
            deb = [r for r in real if r["label"] == "debatable"]
            fp = [r for r in real if r["label"] in ("fp-analyzer", "fp-policy")]
            b = "**" if kind == "all routine" else ""
            w(f"| {b}{kind}{b} | {tier} | {len(sel)} | {len(p)} | {len(env)} | {len(real)} | {pct(len(real), len(sel))} | "
              f"{len(exp)} | {len(deb)} | {len(fp)} | {pct(len(fp), len(sel))} |")
    w("")
    unrev = [r for r in rows if r.get("label") == "unreviewed"]
    if unrev:
        w(f"**{len(unrev)} prompts have no review rule yet.**\n")

    # Causes
    w("## False positives by cause\n")
    w("| Rule | Label | Why | Prompts (plan, tier) |")
    w("|---|---|---|---|")
    causes = Counter()
    for r in rows:
        for x in r.get("review", []):
            if x["label"] != "expected":
                causes[(x["rule"], x["label"], x["why"])] += 1
    for (rule, lab, why), n in sorted(causes.items(), key=lambda kv: -kv[1]):
        w(f"| {rule} | {lab} | {why} | {n} |")
    w("")

    # Prompts
    w("## Every routine prompt\n")
    w("| Root | Plan | Tier | Verdict | Label | Rule: review | Evidence (first 3) |")
    w("|---|---|---|---|---|---|---|")
    for r in sorted((r for r in rows if r["kind"] in ROUTINE and r["verdict"] != "allow"), key=lambda r: (r["slug"], r["kind"], r["tier"])):
        rev = "<br>".join(f"{x['rule']}: {x['label']} ({x['why']})" for x in r["review"])
        ev = []
        for f in r["findings"]:
            if f["rule"] in r["drivers"]:
                ev += f["evidence"]
        if "deletes" in r["drivers"]:
            ev += [a + " (delete)" for a in r["deleted"]]
        evs = "<br>".join("`" + e.replace("|", "\\|") + "`" for e in ev[:3]) + (f"<br>(+{len(ev) - 3} more)" if len(ev) > 3 else "")
        w(f"| {r['slug']} | {r['kind']} | {r['tier']} | {r['verdict']} | {r['label']} | {rev} | {evs} |")
    w("")

    # Control
    w("## Control: destroy plans\n")
    w("| Tier | Destroy plans | With deletes | Prompted (of those with deletes) |")
    w("|---|---|---|---|")
    for tier in ("protected", "standard"):
        sel = [r for r in rows if r["kind"] == "destroy" and r["tier"] == tier]
        dl = [r for r in sel if r["counts"]["delete"] > 0]
        pr = [r for r in dl if r["verdict"] != "allow"]
        w(f"| {tier} | {len(sel)} | {len(dl)} | {len(pr)} |")
    w("")

    # Roots without a plan
    w("## Roots that produced no plan\n")
    w("| Root | Failed step | First error |")
    w("|---|---|---|")
    for rt in roots:
        if "create" not in rt["plans"]:
            err = (rt["error"] or "no error recorded").replace("|", "\\|")
            w(f"| {rt['slug']} | {rt['failed_step'] or '-'} | {err[:160]} |")
    w("")
    open(os.path.join(d, "summary.md"), "w").write("\n".join(L) + "\n")
    print("wrote", os.path.join(d, "summary.md"))


if __name__ == "__main__":
    main()
