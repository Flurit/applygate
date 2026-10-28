#!/usr/bin/env python3
"""Replay the scenario pack against a guard's Claude Code PreToolUse hook.

Throwaway v0-style runner, kept for comparing seatbelt with other guards.
It builds synthetic hook events and pipes them to the guard's hook command.
It NEVER executes the commands inside the scenarios, never uses a shell, and
runs the guard with an empty PATH, a fake HOME and no cloud credentials.

Usage:
  python3 -I harness/run.py --guard bin/seatbelt              # seatbelt (default args)
  python3 -I harness/run.py --guard-cmd "/path/to/other-guard --hook" --name other
  python3 -I harness/run.py --guard bin/seatbelt --json results.json --md results.md
"""

import argparse
import datetime
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.join(HERE, "pack")


def materialize(tmp):
    shutil.copytree(PACK, tmp, dirs_exist_ok=True)
    home = os.path.join(tmp, "home")
    os.makedirs(os.path.join(home, ".aws"), exist_ok=True)
    return os.path.join(tmp, "fixtures", "repo"), os.path.join(tmp, "plans"), home


def event(s, repo, home):
    def sub(v):
        return v.replace("{repo}", repo).replace("{home}", home) if isinstance(v, str) else v

    return {
        "session_id": "replay-" + s["id"],
        "transcript_path": "/dev/null",
        "cwd": os.path.join(repo, s.get("cwd", "")),
        "permission_mode": s.get("permission_mode", "default"),
        "hook_event_name": "PreToolUse",
        "tool_name": s["tool"],
        "tool_input": {k: sub(v) for k, v in s["tool_input"].items()},
        "tool_use_id": "toolu_replay_" + s["id"],
    }


def parse_output(proc):
    if proc.returncode == 2:
        return "block", proc.stderr
    if proc.returncode != 0:
        return "error", proc.stderr
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
    ap.add_argument("--name", default="seatbelt")
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--timeout", type=float, default=30)
    a = ap.parse_args()

    with open(os.path.join(PACK, "scenarios.json")) as f:
        pack = json.load(f)
    tmp = tempfile.mkdtemp(prefix="seatbelt-replay-")
    try:
        repo, plans, home = materialize(tmp)
        env = {
            "HOME": home, "USER": "agent", "PATH": "/nonexistent",
            "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
            "XDG_STATE_HOME": os.path.join(tmp, "state"), "XDG_CONFIG_HOME": os.path.join(tmp, "config"),
        }
        results = []
        for s in pack["scenarios"]:
            if a.guard:
                cmd = [os.path.abspath(a.guard), "hook", "claude", "--no-log"]
                for planfile, fixture in (s.get("plans") or {}).items():
                    cmd += ["--plan-json", planfile + "=" + os.path.join(plans, fixture)]
            else:
                cmd = shlex.split(a.guard_cmd)
            e = dict(env, **(s.get("env") or {}))
            t0 = time.perf_counter()
            try:
                proc = subprocess.run(cmd, input=json.dumps(event(s, repo, home)), capture_output=True,
                                      text=True, env=e, timeout=a.timeout, cwd=tmp, shell=False)
                verdict, msg = parse_output(proc)
            except subprocess.TimeoutExpired:
                verdict, msg = "error", "timeout"
            ms = (time.perf_counter() - t0) * 1000
            results.append({"id": s["id"], "spec": s["spec"], "kind": s["kind"], "title": s["title"],
                            "expect": s["expect"], "verdict": verdict, "pass": verdict in s["expect"],
                            "ms": round(ms, 2), "message": msg})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    dang = [r for r in results if r["kind"] == "dangerous"]
    ben = [r for r in results if r["kind"] == "benign"]
    caught = sum(r["verdict"] in ("block", "ask") for r in dang)
    flagged = sum(r["verdict"] != "allow" for r in ben)
    errors = sum(r["verdict"] == "error" for r in results)
    ms = sorted(r["ms"] for r in results)
    p = lambda q: ms[min(len(ms) - 1, int(len(ms) * q))]
    summary = {"guard": a.name, "date": datetime.date.today().isoformat(), "pack_version": pack["version"],
               "dangerous_caught": caught, "dangerous": len(dang), "benign_flagged": flagged, "benign": len(ben),
               "errors": errors, "exact": sum(r["pass"] for r in results), "total": len(results),
               "latency_ms_p50": p(0.5), "latency_ms_p95": p(0.95)}
    print(json.dumps(summary))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"summary": summary, "results": results}, f, indent=1)
    if a.md:
        with open(a.md, "w") as f:
            f.write(f"# Replay: {a.name}\n\n{summary['date']}, pack v{summary['pack_version']}, process per event (includes start-up).\n\n")
            f.write(f"- dangerous caught (block or ask): {caught}/{len(dang)}\n- benign flagged: {flagged}/{len(ben)}\n")
            f.write(f"- matched exact expectation: {summary['exact']}/{summary['total']}\n- errors: {errors}\n")
            f.write(f"- latency per event, ms: p50 {summary['latency_ms_p50']}, p95 {summary['latency_ms_p95']}\n\n")
            f.write("| ID | Spec | Kind | Scenario | Expected | Got |\n|---|---|---|---|---|---|\n")
            for r in results:
                mark = "" if r["pass"] else " **(mismatch)**"
                f.write(f"| {r['id']} | {r['spec']} | {r['kind']} | {r['title']} | {'/'.join(r['expect'])} | {r['verdict']}{mark} |\n")
    return 0 if summary["exact"] == summary["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
