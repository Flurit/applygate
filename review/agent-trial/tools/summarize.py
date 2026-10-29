#!/usr/bin/env python3
"""Build the hand-review template for one collected trial run.

    summarize.py RESULTS_DIR [--agent "NAME VERSION"]... > summary.md

Reads decisions.jsonl, versions.txt, report.txt, doctor/*.txt and, when the
plan-gate exercise ran, plangate/verdicts.md. Writes Markdown: the run's
metadata, allow/ask/block counts per repository, every ask and block with an
empty "False positive?" column for hand review, and the agent-task log to
fill in. Reads files only; never runs anything.
"""
import json
import os
import sys
from collections import Counter, defaultdict

LABELS = "expected | fp-policy | fp-analyzer | fp-environment | debatable | miss"


def repo_of(cwd):
    parts = cwd.strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "work":
        return parts[1]
    return cwd or "(no cwd)"


def rel(cwd):
    parts = cwd.strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "work":
        return "/".join(parts[2:]) or "."
    return cwd


def cell(s, limit=120):
    s = (s or "").replace("|", "\\|").replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    agents = []
    args = sys.argv[2:]
    while args:
        if args[0] == "--agent" and len(args) > 1:
            agents.append(args[1])
            args = args[2:]
        else:
            args = args[1:]

    def read(name):
        p = os.path.join(out, name)
        return open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""

    entries, bad = [], 0
    for line in read("decisions.jsonl").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            bad += 1

    versions = dict(
        (k.strip(), v.strip())
        for k, _, v in (l.partition(":") for l in read("versions.txt").splitlines())
        if _
    )
    date = os.path.basename(os.path.normpath(out))
    print(f"# Agent-driven observe-mode trial: results {date}")
    print()
    print("**Trial type:** agent-driven trial, not a team trial. The agents worked the fixed")
    print("task list in `tasks.md` on clones of the five public repositories from")
    print("`review/oss-corpus/repos.txt`, in observe mode, with LocalStack as the only AWS")
    print("endpoint and no cloud credentials.")
    print()
    print("| Field | Value |")
    print("|---|---|")
    print(f"| Date | {date} |")
    print(f"| seatbelt | {versions.get('seatbelt', 'unknown')} |")
    if agents:
        print(f"| Agents | {'; '.join(agents)} |")
    else:
        print(f"| Agents (installed) | Claude Code {versions.get('claude-code', '?')}; Codex {versions.get('codex', '?')} (fill in which ones ran) |")
    print(f"| Terraform | {versions.get('terraform', 'unknown')} |")
    print(f"| Machine | {versions.get('container', 'unknown')} (container); host: _fill in_ |")
    print(f"| Collected | {versions.get('collected', 'unknown')} |")
    print(f"| Decisions | {len(entries)} (malformed lines: {bad}) |")
    print()

    # Counts per repository.
    per = defaultdict(Counter)
    for e in entries:
        r = repo_of(e.get("cwd", ""))
        per[r]["total"] += 1
        per[r][e.get("verdict", "?")] += 1
        if e.get("mode") == "observe" and e.get("verdict") != "allow":
            per[r]["would"] += 1
        if e.get("error"):
            per[r]["errors"] += 1
    print("## Counts (policy verdicts; in observe mode every decision is enforced as allow)")
    print()
    print("| Repository | Decisions | Allow | Ask | Block | Would have asked or blocked (observe) | Internal errors | False positives | FP rate |")
    print("|---|---|---|---|---|---|---|---|---|")
    tot = Counter()
    for r in sorted(per):
        c = per[r]
        tot.update(c)
        print(f"| {r} | {c['total']} | {c['allow']} | {c['ask']} | {c['block']} | {c['would']} | {c['errors']} | _fill in_ | _fill in_ |")
    print(f"| **All** | **{tot['total']}** | **{tot['allow']}** | **{tot['ask']}** | **{tot['block']}** | **{tot['would']}** | **{tot['errors']}** | _fill in_ | _fill in_ |")
    print()
    print("False-positive rate = false positives / decisions (after removing noise such as")
    print("commands the agent never meant to run). Gate: under 5% per repository.")
    print()

    flagged = [e for e in entries if e.get("verdict") in ("ask", "block") or e.get("error")]
    print(f"## Every ask and block ({len(flagged)}), for hand review")
    print()
    print(f"Fill the last column with one of: {LABELS}.")
    print()
    print("| # | Time (UTC) | Agent | Repo | Dir | Tool | Command or paths | Verdict | Class | Tier | Why / findings | False positive? |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for i, e in enumerate(flagged, 1):
        acts = e.get("actions") or []
        flagged_acts = [a for a in acts if a.get("verdict") in ("ask", "block")] or acts[:1]
        classes = ", ".join(sorted({a.get("class", "") for a in flagged_acts})) or "-"
        tiers = ", ".join(sorted({a.get("tier", "") for a in flagged_acts if a.get("tier")})) or "-"
        why = []
        for a in flagged_acts:
            if a.get("why"):
                why.append(a["why"])
            for f in a.get("findings") or []:
                if f.get("severity") in ("critical", "high", "medium"):
                    why.append(f"{f.get('severity')} {f.get('rule')}: {f.get('message')}")
        if e.get("error"):
            why.append("error: " + e["error"])
        what = e.get("command") or ", ".join(e.get("paths") or [])
        print(
            f"| {i} | {cell(e.get('time', ''), 20)} | {e.get('agent', '')} | {repo_of(e.get('cwd', ''))} | {cell(rel(e.get('cwd', '')), 40)} | {e.get('tool', '')} | `{cell(what, 100)}` | {e.get('verdict')} | {classes} | {tiers} | {cell(' / '.join(why), 160)} | |"
        )
    if not flagged:
        print("| | | | | | | (none) | | | | | |")
    print()

    print("## Agent task log")
    print()
    print("One row per task given (ids from `tasks.md`). Outcome: what the agent did and")
    print("whether the expected verdicts appeared in the log.")
    print()
    print("| Task | Agent (version) | Started (UTC) | Outcome | Verdicts seen | Notes |")
    print("|---|---|---|---|---|---|")
    print("| | | | | | |")
    print()

    rep = read("report.txt")
    if rep:
        print("## `seatbelt report`")
        print()
        print("```")
        print(rep.rstrip())
        print("```")
        print()

    doctor_dir = os.path.join(out, "doctor")
    if os.path.isdir(doctor_dir):
        print("## `seatbelt doctor` per clone")
        print()
        for name in sorted(os.listdir(doctor_dir)):
            txt = read(os.path.join("doctor", name)).rstrip()
            warns = sum(1 for l in txt.splitlines() if l.startswith("WARN"))
            print(f"### {name[:-4]} ({'clean' if warns == 0 else str(warns) + ' warning(s)'})")
            print()
            print("```")
            print(txt)
            print("```")
            print()

    diff_dir = os.path.join(out, "diff")
    if os.path.isdir(diff_dir):
        print("## Agent changes per clone (`git status --short`, line counts of the diff)")
        print()
        print("| Clone | Changed files | Diff lines |")
        print("|---|---|---|")
        for name in sorted(os.listdir(diff_dir)):
            txt = read(os.path.join("diff", name))
            status, _, diff = txt.partition("\n\n")
            files = len([l for l in status.splitlines() if l.strip()])
            print(f"| {name[:-6]} | {files} | {len(diff.splitlines())} |")
        print()

    pg = read(os.path.join("plangate", "verdicts.md"))
    if pg:
        print("## Plan-gate exercise (no agent; `plangate/verdicts.md`)")
        print()
        print("\n".join(l for l in pg.splitlines() if not l.startswith("# ")))
        print()


if __name__ == "__main__":
    main()
