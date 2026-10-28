#!/usr/bin/env python3
"""Label every ask/block in a replay result after hand review.

The rules below encode the review decisions; each FP rule names the commands
it covers so the labels can be checked. Usage: label.py RESULT.jsonl
Prints a JSON summary and writes RESULT.labels.jsonl.
"""
import json
import re
import sys
from collections import Counter, defaultdict

PLACEHOLDER = re.compile(r"<[A-Za-z_][\w./-]*>|\[[a-z]+(\|[a-z]+)+\]")
WRAPPER = re.compile(r"\b(aws-vault|aws-okta|gds aws|saml2aws|aws-sso|doppler run|op run|chamber exec|infisical run|envchain)\b")

# Hand-review decisions for flagged commands that should have been allowed.
FALSE_POSITIVES = [
    # (label, why, predicate)
    ("fp-policy", "terraform init -reconfigure used to switch per-environment backends; spec classes it as state surgery",
     lambda r: "init" in r["command"] and "-reconfigure" in r["command"]),
    ("fp-analyzer", "Makefile recipe calls a make function ($(call ...)) the analyzer does not expand",
     lambda r: r["command"] == "make lint_docs"),
    ("fp-analyzer", "while $(kill -0 PID): substitution output used as the program name",
     lambda r: "kill -0" in r["command"]),
    ("fp-analyzer", "git command held in a variable built from a runtime loop value (${git} reflog ...)",
     lambda r: r["source"].endswith("mirror-repos.yml")),
    ("fp-analyzer", "aws eks update-kubeconfig only writes local kubeconfig (fixed: now read-only)",
     lambda r: "update-kubeconfig" in r["command"] and all(a["class"] == "cloud-write" for a in r["actions"])),
    ("fp-analyzer", "kubectl relay/port-forward opens a local tunnel (fixed: now read-only)",
     lambda r: re.search(r"kubectl (relay|port-forward|proxy)", r["command"]) is not None),
    ("fp-analyzer", "exec \"$@\" entrypoint: positional parameters not expanded (fixed: \"$@\" now resolves)",
     lambda r: r["command"].endswith("unprivileged-entrypoint.sh")),
    ("fp-environment", "source of a virtualenv that does not exist in a fresh clone",
     lambda r: r["command"].startswith("source venv/")),
]
DEBATABLE = [
    ("debatable-policy", "read-only AWS SDK script asks (accepted cost of asking on SDK code in protected/standard tiers)",
     lambda r: r["command"].endswith("iam-policy-generator.py")),
    ("debatable-policy", "kubectl delete of example manifests in a disposable tier asks (spec: cloud-destructive in disposable = ask)",
     lambda r: all(a["class"] == "cloud-destructive" and a["tier"] == "disposable" for a in r["actions"])),
]


def label(r):
    acts = r["actions"]
    parse_only = acts and all(a["why"].startswith("could not parse as shell") for a in acts)
    if re.match(r"^source\s*(=>|=)", r["command"]):
        return "noise", "configuration text (HCL/logstash), not a command"
    if parse_only:
        if PLACEHOLDER.search(r["command"]):
            return "placeholder", "documentation placeholder such as <clusterName> makes the line unparseable"
        return "noise", "not shell (HCL, JSON, YAML, code, tree diagrams) extracted from a code fence"
    if PLACEHOLDER.search(r["command"]) and all(a["class"] in ("dynamic", "cloud-write") for a in acts):
        return "placeholder", "documentation placeholder changes how the line parses"
    for lab, why, pred in FALSE_POSITIVES + DEBATABLE:
        if pred(r):
            return lab, why
    return "expected", "ask/block matches the policy for the command and tier"


def main():
    path = sys.argv[1]
    rows = [json.loads(l) for l in open(path)]
    out = []
    by_repo = defaultdict(Counter)
    why = Counter()
    for r in rows:
        if r["verdict"] == "allow":
            lab, w = "allow", ""
        else:
            lab, w = label(r)
            why[(lab, w)] += 1
        r["review"] = lab
        out.append(r)
        by_repo[r["repo"]][lab] += 1
        by_repo["ALL"][lab] += 1
    with open(path.replace(".jsonl", ".labels.jsonl"), "w") as f:
        for r in out:
            f.write(json.dumps(r) + "\n")
    summary = {}
    for repo, c in by_repo.items():
        total = sum(c.values())
        runnable = total - c["noise"] - c["placeholder"]
        fp = c["fp-policy"] + c["fp-analyzer"] + c["fp-environment"]
        summary[repo] = dict(c, total=total, runnable=runnable, false_positives=fp,
                             fp_rate=round(100 * fp / runnable, 2) if runnable else None,
                             fp_rate_incl_debatable=round(100 * (fp + c["debatable-policy"]) / runnable, 2) if runnable else None)
    print(json.dumps({"summary": summary, "reasons": [[k[0], k[1], v] for k, v in why.most_common()]}, indent=1))


if __name__ == "__main__":
    main()
