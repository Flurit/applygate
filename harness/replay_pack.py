#!/usr/bin/env python3
"""Replay any scenario pack against a guard's Claude Code PreToolUse hook, in a chosen fixture.

Added by the independent review. Same safety rules as run.py: commands are only
ever strings inside synthetic events; nothing in a scenario is executed, no shell
is used, and the guard runs with an empty PATH, a fake HOME and no credentials.

Accepts the short scenario form ({"id","kind","command"}) as well as run.py's
form ({"tool","tool_input",...}). Optional per-scenario fields: cwd, expect,
must_mention, permission_mode, env, files (relative path -> content, written
into the fixture copy before the event is sent).

Usage:
  python3 -I harness/replay_pack.py --guard bin/seatbelt \
      --pack harness/pack_v0_original/scenarios.json \
      --fixture harness/pack_v0_original/fixtures/protected --label protected \
      --json out.json --md out.md
"""

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


def parse_output(proc):
    if proc.returncode == 2:
        return "block", proc.stderr.strip()
    if proc.returncode != 0:
        return "error", "exit %d: %s" % (proc.returncode, proc.stderr.strip())
    out = proc.stdout.strip()
    if not out:
        return "allow", ""
    try:
        h = json.loads(out).get("hookSpecificOutput", {})
    except json.JSONDecodeError:
        return "error", out
    d = h.get("permissionDecision", "allow")
    return {"deny": "block", "ask": "ask", "allow": "allow"}.get(d, "error"), h.get("permissionDecisionReason", "")


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--guard", help="path to the seatbelt binary")
    g.add_argument("--guard-cmd", help="any guard's hook command (string, split with shlex)")
    ap.add_argument("--pack", required=True)
    ap.add_argument("--fixture", required=True, help="directory copied to a temp repo for each run")
    ap.add_argument("--label", default="")
    ap.add_argument("--permission-mode", default="default")
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--timeout", type=float, default=30)
    a = ap.parse_args()

    with open(a.pack) as f:
        scenarios = json.load(f)["scenarios"]
    results = []
    for s in scenarios:
        # Fresh copy per scenario so files written by one case cannot affect another.
        tmp = tempfile.mkdtemp(prefix="sbreview-")
        try:
            repo = os.path.join(tmp, "repo")
            shutil.copytree(a.fixture, repo, symlinks=True)
            home = os.path.join(tmp, "home")
            os.makedirs(os.path.join(home, ".aws"))
            for rel, content in (s.get("files") or {}).items():
                p = os.path.join(repo, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write(content)
            for rel, target in (s.get("symlinks") or {}).items():
                p = os.path.join(repo, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                os.symlink(target, p)
            tool = s.get("tool", "Bash")
            tin = s.get("tool_input") or {"command": s["command"]}
            tin = {k: v.replace("{repo}", repo).replace("{home}", home) if isinstance(v, str) else v
                   for k, v in tin.items()}
            ev = {"session_id": "review-" + s["id"], "transcript_path": "/dev/null",
                  "cwd": os.path.join(repo, s.get("cwd", "")),
                  "permission_mode": s.get("permission_mode", a.permission_mode),
                  "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tin,
                  "tool_use_id": "toolu_review_" + s["id"]}
            env = {"HOME": home, "USER": "agent", "PATH": "/nonexistent",
                   "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
                   "XDG_STATE_HOME": os.path.join(tmp, "state"), "XDG_CONFIG_HOME": os.path.join(tmp, "config")}
            env.update(s.get("env") or {})
            cmd = ([os.path.abspath(a.guard), "hook", "claude", "--no-log"] if a.guard else shlex.split(a.guard_cmd))
            t0 = time.perf_counter()
            try:
                proc = subprocess.run(cmd, input=json.dumps(ev), capture_output=True, text=True, env=env,
                                      timeout=a.timeout, cwd=tmp, shell=False)
                verdict, msg = parse_output(proc)
            except subprocess.TimeoutExpired:
                verdict, msg = "error", "timeout"
            ms = (time.perf_counter() - t0) * 1000
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        msg = msg.replace(tmp, "<tmp>")
        expect = s.get("expect") or (["block", "ask"] if s["kind"] == "dangerous" else ["allow"])
        missing = [m for m in s.get("must_mention", []) if m not in msg]
        results.append({"id": s["id"], "kind": s["kind"], "tier": a.label, "command": tin.get("command", json.dumps(tin)),
                        "verdict": verdict, "expect": expect, "pass": verdict in expect and not missing,
                        "missing_mentions": missing, "ms": round(ms, 2), "reason": msg})

    dang = [r for r in results if r["kind"] == "dangerous"]
    ben = [r for r in results if r["kind"] == "benign"]
    summary = {"label": a.label, "pack": a.pack,
               "dangerous_caught": sum(r["verdict"] in ("block", "ask") for r in dang), "dangerous": len(dang),
               "benign_flagged": sum(r["verdict"] != "allow" for r in ben), "benign": len(ben),
               "errors": sum(r["verdict"] == "error" for r in results),
               "pass": sum(r["pass"] for r in results), "total": len(results)}
    print(json.dumps(summary))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"summary": summary, "results": results}, f, indent=1)
    if a.md:
        esc = lambda t: t.replace("|", "\\|").replace("\n", " ")
        with open(a.md, "w") as f:
            f.write(f"| id | tier | command | verdict | expected | reason |\n|---|---|---|---|---|---|\n")
            for r in results:
                mark = "" if r["pass"] else " **✗**"
                f.write(f"| {r['id']} | {r['tier']} | `{esc(r['command'])}` | {r['verdict']}{mark} | "
                        f"{'/'.join(r['expect'])} | {esc(r['reason'])[:220]} |\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
