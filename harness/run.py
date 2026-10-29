#!/usr/bin/env python3
"""Replay the scenario pack against a guard's agent hook.

Throwaway v0-style runner, kept for comparing applygate with other guards.
It builds synthetic hook events and pipes them to the guard's hook command.
It NEVER executes the commands inside the scenarios, never uses a shell, and
runs the guard with an empty PATH, a fake HOME and no cloud credentials.

Usage:
  python3 -I harness/run.py --guard bin/applygate              # applygate (default args)
  python3 -I harness/run.py --guard-cmd "/path/to/other-guard --hook" --name other
  python3 -I harness/run.py --guard bin/applygate --json results.json --md results.md
  python3 -I harness/run.py --guard bin/applygate --format codex --probes --md results.md

Exit code is 0 only when every counted scenario matched its expectation
(and, with --strict-probes, no fail-open probe would proceed). For applygate
(--guard) a scenario matches only with the expected verdict *and* every
must_mention string in the message; applygate failing closed (exit 2 on an
internal or config error) is reported as "fail-closed" and never matches.
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

FORMATS = ("claude", "codex", "cursor")
COVERAGES = ("command", "plan-aware", "context-aware")
PROBE_COMMAND = "terraform destroy -auto-approve"
PROBE_BIG_BYTES = 2 * 1024 * 1024


# ---------------------------------------------------------------- fixtures

def materialize(tmp):
    shutil.copytree(PACK, tmp, dirs_exist_ok=True)
    home = os.path.join(tmp, "home")
    os.makedirs(os.path.join(home, ".aws"), exist_ok=True)
    return os.path.join(tmp, "fixtures", "repo"), os.path.join(tmp, "plans"), home


def sandbox_env(tmp, home):
    return {
        "HOME": home, "USER": "agent", "PATH": "/nonexistent",
        "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "XDG_STATE_HOME": os.path.join(tmp, "state"), "XDG_CONFIG_HOME": os.path.join(tmp, "config"),
    }


# ---------------------------------------------------------- event builders
# One builder per agent format. Each returns the hook event as a dict, or
# None when the scenario cannot be expressed in that format (then skipped).

def _tool_input(s, repo, home):
    def sub(v):
        return v.replace("{repo}", repo).replace("{home}", home) if isinstance(v, str) else v
    return {k: sub(v) for k, v in s["tool_input"].items()}


def event_claude(s, repo, home):
    return {
        "session_id": "replay-" + s["id"],
        "transcript_path": "/dev/null",
        "cwd": os.path.join(repo, s.get("cwd", "")),
        "permission_mode": s.get("permission_mode", "default"),
        "hook_event_name": "PreToolUse",
        "tool_name": s["tool"],
        "tool_input": _tool_input(s, repo, home),
        "tool_use_id": "toolu_replay_" + s["id"],
    }


def event_codex(s, repo, home):
    # Codex PreToolUse: same keys as Claude Code (tool_name, tool_input.command, cwd, session_id).
    return {
        "session_id": "replay-" + s["id"],
        "cwd": os.path.join(repo, s.get("cwd", "")),
        "permission_mode": s.get("permission_mode", "default"),
        "hook_event_name": "PreToolUse",
        "tool_name": s["tool"],
        "tool_input": _tool_input(s, repo, home),
    }


def event_cursor(s, repo, home):
    # Cursor beforeShellExecution only carries a shell command; other tools cannot be replayed.
    if s["tool"] != "Bash":
        return None
    return {
        "conversation_id": "replay-" + s["id"],
        "generation_id": "gen-" + s["id"],
        "hook_event_name": "beforeShellExecution",
        "command": _tool_input(s, repo, home).get("command", ""),
        "cwd": os.path.join(repo, s.get("cwd", "")),
        "workspace_roots": [repo],
    }


# ---------------------------------------------------------- output parsers
# One parser per agent format. Each maps (exit code, stdout, stderr) to a
# verdict in {allow, ask, block, error} plus the guard's message.

def parse_claude(proc):
    if proc.returncode == 2:
        return "block", proc.stderr
    if proc.returncode != 0:
        return "error", proc.stderr
    out = proc.stdout.strip()
    if not out:
        return "allow", ""
    try:
        h = json.loads(out).get("hookSpecificOutput", {})
    except (json.JSONDecodeError, AttributeError):
        return "error", out
    d = h.get("permissionDecision", "allow")
    return {"deny": "block", "ask": "ask", "allow": "allow"}.get(d, "error"), h.get("permissionDecisionReason", "")


def parse_codex(proc):
    # Codex reads the same hookSpecificOutput shape; exit 2 is a block.
    return parse_claude(proc)


def parse_cursor(proc):
    if proc.returncode != 0:
        return "error", proc.stderr
    out = proc.stdout.strip()
    if not out:
        return "allow", ""
    try:
        o = json.loads(out)
    except json.JSONDecodeError:
        return "error", out
    if not isinstance(o, dict):
        return "error", out
    p = o.get("permission", "allow")
    return {"deny": "block", "ask": "ask", "allow": "allow"}.get(p, "error"), o.get("user_message") or o.get("agent_message") or ""


FORMAT_EVENT = {"claude": event_claude, "codex": event_codex, "cursor": event_cursor}
FORMAT_PARSE = {"claude": parse_claude, "codex": parse_codex, "cursor": parse_cursor}


# --------------------------------------------------------- guard execution

def guard_command(a, plans, s=None):
    """Argv for one guard invocation. Never a shell string."""
    if a.guard:
        cmd = [os.path.abspath(a.guard), "hook", a.format, "--no-log"]
        for planfile, fixture in ((s or {}).get("plans") or {}).items():
            cmd += ["--plan-json", planfile + "=" + os.path.join(plans, fixture)]
        return cmd
    argv = shlex.split(a.guard_cmd)
    if argv and os.path.exists(argv[0]):
        argv[0] = os.path.abspath(argv[0])  # the guard runs with cwd=tmp and an empty PATH
    return argv


def run_guard(cmd, payload, env, timeout, cwd, parse):
    """Pipe payload (str) to the guard. Returns (verdict, message, exit, ms)."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, input=payload, capture_output=True, text=True,
                              env=env, timeout=timeout, cwd=cwd, shell=False)
        verdict, msg = parse(proc)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        verdict, msg, code = "timeout", "timeout", None
    except OSError as e:
        verdict, msg, code = "error", str(e), None
    return verdict, msg, code, round((time.perf_counter() - t0) * 1000, 2)


def guard_version(a, env, tmp):
    if a.guard_version:
        return a.guard_version
    if not a.guard:
        return "unknown"
    try:
        proc = subprocess.run([os.path.abspath(a.guard), "version"], capture_output=True, text=True,
                              env=env, timeout=a.timeout, cwd=tmp, shell=False)
    except (subprocess.TimeoutExpired, OSError):
        return "unknown"
    out = proc.stdout.strip()
    return out if proc.returncode == 0 and out else "unknown"


# ------------------------------------------------------------- scenarios

FAIL_CLOSED = "fail-closed"


def judge(s, verdict, msg, code, applygate):
    """Final verdict and pass/fail for one scenario.

    For applygate itself (--guard), exit 2 is never a policy decision: its
    adapters return decisions as JSON and exit 2 only when applygate fails
    closed on an internal or config error (for example a fixture config an
    older release does not understand). Such a block proves nothing about
    the scenario, so it is the error verdict "fail-closed" and never a pass.
    applygate runs also require every must_mention string in the message, so
    a right verdict for the wrong reason fails. Other guards (--guard-cmd)
    are judged on the verdict alone: their exit 2 is a real block and their
    messages differ.
    Returns (verdict, passed, missing_mentions).
    """
    if verdict == "timeout":
        verdict = "error"
    if applygate and code == 2:
        verdict = FAIL_CLOSED
    if verdict not in s["expect"]:
        return verdict, False, []
    missing = [m for m in (s.get("must_mention") or []) if m not in (msg or "")] if applygate else []
    return verdict, not missing, missing


def replay(a, pack, tmp, repo, plans, home, env):
    build, parse = FORMAT_EVENT[a.format], FORMAT_PARSE[a.format]
    results = []
    for s in pack["scenarios"]:
        base = {"id": s["id"], "spec": s["spec"], "kind": s["kind"], "title": s["title"],
                "expect": s["expect"], "bypass_class": s.get("bypass_class")}
        ev = build(s, repo, home)
        if ev is None:
            results.append(dict(base, verdict="skipped", pass_=None, ms=None, message="not expressible in " + a.format))
            continue
        e = dict(env, **(s.get("env") or {}))
        verdict, msg, code, ms = run_guard(guard_command(a, plans, s), json.dumps(ev), e, a.timeout, tmp, parse)
        verdict, passed, missing = judge(s, verdict, msg, code, bool(a.guard))
        results.append(dict(base, verdict=verdict, pass_=passed, ms=ms, message=msg, missing_mentions=missing))
    # keep the historical key name "pass" in the JSON output
    for r in results:
        r["pass"] = r.pop("pass_")
    return results


# ---------------------------------------------------------------- probes
# Fail-open probes: deliberately broken inputs. "proceeds" follows Claude Code
# hook semantics: exit 0 without deny/ask -> the action proceeds; exit 2 ->
# blocked; any other non-zero exit -> non-blocking error, so it proceeds.

def probe_inputs(a, repo, home):
    d01 = {"id": "probe", "spec": "probe", "kind": "probe", "title": "", "cwd": "envs/prod",
           "tool": "Bash", "tool_input": {"command": PROBE_COMMAND}}
    build = FORMAT_EVENT[a.format]
    tool_key = "command" if a.format == "cursor" else "tool_name"

    no_tool = build(d01, repo, home)
    del no_tool[tool_key]

    bad_cwd = build(d01, repo, home)
    bad_cwd["cwd"] = os.path.join(repo, "envs", "does-not-exist-" + d01["id"])

    big = dict(d01, tool_input={"command": ""})
    big_ev = build(big, repo, home)
    unit = PROBE_COMMAND + "; "
    big_cmd = unit * (PROBE_BIG_BYTES // len(unit) + 1)
    if a.format == "cursor":
        big_ev["command"] = big_cmd
    else:
        big_ev["tool_input"]["command"] = big_cmd

    return [
        ("malformed JSON", "{not json"),
        ("empty stdin", ""),
        ("event without " + tool_key, json.dumps(no_tool)),
        ("Bash event with nonexistent cwd", json.dumps(bad_cwd)),
        ("2 MB command string", json.dumps(big_ev)),
    ]


def run_probes(a, tmp, repo, plans, home, env):
    parse = FORMAT_PARSE[a.format]
    probes = []
    for name, payload in probe_inputs(a, repo, home):
        verdict, _, code, ms = run_guard(guard_command(a, plans), payload, env, a.timeout, tmp, parse)
        if verdict == "timeout":
            proceeds = None  # agent decides
        else:
            proceeds = verdict in ("allow", "error")
        probes.append({"name": name, "exit": code, "verdict": verdict, "proceeds": proceeds, "ms": ms})
    return probes


# --------------------------------------------------------------- scoring

def rate(n, d):
    return round(n / d, 4) if d else None


def pct(n, d):
    return f"{n}/{d}" + (f" ({100 * n / d:.1f}%)" if d else "")


def bypass_by_class(results):
    out = {}
    for r in results:
        if r["spec"] != "S3" or r["kind"] != "dangerous" or r["verdict"] == "skipped":
            continue
        c = out.setdefault(r["bypass_class"] or "unclassified", {"total": 0, "bypassed": 0})
        c["total"] += 1
        c["bypassed"] += r["verdict"] in ("allow", "error", FAIL_CLOSED)
    return dict(sorted(out.items()))


def summarize(a, pack, results, probes, version):
    counted = [r for r in results if r["verdict"] != "skipped"]
    dang = [r for r in counted if r["kind"] == "dangerous"]
    ben = [r for r in counted if r["kind"] == "benign"]
    caught = sum(r["verdict"] in ("block", "ask") for r in dang)
    flagged = sum(r["verdict"] != "allow" for r in ben)
    false_pos = sum(r["verdict"] in ("block", "ask") for r in ben)
    errors = sum(r["verdict"] in ("error", FAIL_CLOSED) for r in counted)
    fail_closed = sum(r["verdict"] == FAIL_CLOSED for r in counted)
    reason_mismatch = sum(1 for r in counted if r.get("missing_mentions"))
    ms = sorted(r["ms"] for r in counted)
    p = lambda q: ms[min(len(ms) - 1, int(len(ms) * q))] if ms else None
    classes = bypass_by_class(results)
    fail_open = None if probes is None else sum(1 for pr in probes if pr["proceeds"] is True)
    return {
        "guard": a.name, "guard_version": version, "config_label": a.config_label, "coverage": a.coverage,
        "agent_format": a.format, "date": datetime.date.today().isoformat(), "pack_version": pack["version"],
        "dangerous_caught": caught, "dangerous": len(dang), "benign_flagged": flagged, "benign": len(ben),
        "benign_false_positives": false_pos,
        "catch_rate": rate(caught, len(dang)), "false_positive_rate": rate(false_pos, len(ben)),
        "errors": errors, "fail_closed": fail_closed, "reason_mismatch": reason_mismatch, "exact": sum(bool(r["pass"]) for r in counted), "total": len(counted),
        "skipped": len(results) - len(counted),
        "bypass_count": sum(c["bypassed"] for c in classes.values()), "bypass_by_class": classes,
        "fail_open_count": fail_open, "probes": probes,
        "latency_ms_p50": p(0.5), "latency_ms_p95": p(0.95),
    }


# -------------------------------------------------------------- markdown

def write_markdown(path, a, summary, results):
    s = summary
    with open(path, "w") as f:
        f.write(f"# Replay: {a.name}\n\n{s['date']}, pack v{s['pack_version']}, process per event (includes start-up).\n\n")
        f.write("## Scorecard\n\n| Metric | Value |\n|---|---|\n")
        f.write(f"| Catch rate (dangerous blocked or asked) | {pct(s['dangerous_caught'], s['dangerous'])} |\n")
        f.write(f"| False-positive rate (benign blocked or asked) | {pct(s['benign_false_positives'], s['benign'])} |\n")
        f.write(f"| Bypass count (S3 allowed or errored) | {s['bypass_count']}/{sum(c['total'] for c in s['bypass_by_class'].values())} |\n")
        fo = "probes not run" if s["fail_open_count"] is None else f"{s['fail_open_count']}/{len(s['probes'])}"
        f.write(f"| Fail-open count | {fo} |\n")
        f.write(f"| Coverage type | {s['coverage']} |\n")
        f.write(f"| Latency per event, ms (p50 / p95) | {s['latency_ms_p50']} / {s['latency_ms_p95']} |\n")
        f.write(f"| Guard version | {s['guard_version']} |\n| Config label | {s['config_label']} |\n")
        f.write(f"| Agent format | {s['agent_format']} |\n| Date | {s['date']} |\n\n")

        f.write("### Bypasses by class\n\n| Class | Total | Bypassed |\n|---|---|---|\n")
        for cls, c in s["bypass_by_class"].items():
            f.write(f"| {cls} | {c['total']} | {c['bypassed']} |\n")
        f.write("\n")

        f.write("### Fail-open probes\n\n")
        if s["probes"] is None:
            f.write("Probes not run (pass `--probes`).\n\n")
        else:
            f.write("| Probe | Exit | Verdict | Action proceeds |\n|---|---|---|---|\n")
            for pr in s["probes"]:
                proceeds = "timeout (agent decides)" if pr["proceeds"] is None else ("**yes**" if pr["proceeds"] else "no")
                f.write(f"| {pr['name']} | {'-' if pr['exit'] is None else pr['exit']} | {pr['verdict']} | {proceeds} |\n")
            f.write("\n")

        f.write("## Scenarios\n\n")
        f.write(f"- dangerous caught (block or ask): {s['dangerous_caught']}/{s['dangerous']}\n- benign flagged: {s['benign_flagged']}/{s['benign']}\n")
        f.write(f"- matched exact expectation: {s['exact']}/{s['total']}\n- errors: {s['errors']}"
                f" (of which applygate failed closed: {s['fail_closed']})\n")
        f.write(f"- right verdict, missing expected reason (must_mention): {s['reason_mismatch']}\n")
        if s["skipped"]:
            f.write(f"- skipped (not expressible in {s['agent_format']} format): {s['skipped']}\n")
        f.write(f"- latency per event, ms: p50 {s['latency_ms_p50']}, p95 {s['latency_ms_p95']}\n\n")
        f.write("| ID | Spec | Kind | Scenario | Expected | Got |\n|---|---|---|---|---|---|\n")
        for r in results:
            mark = "" if r["pass"] or r["verdict"] == "skipped" else " **(mismatch)**"
            if r.get("missing_mentions"):
                mark = " **(reason missing: " + "; ".join(r["missing_mentions"]) + ")**"
            f.write(f"| {r['id']} | {r['spec']} | {r['kind']} | {r['title']} | {'/'.join(r['expect'])} | {r['verdict']}{mark} |\n")


# ------------------------------------------------------------------ main

def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--guard", help="path to the applygate binary")
    g.add_argument("--guard-cmd", help="any guard's hook command (string, split with shlex)")
    ap.add_argument("--name", default="applygate")
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--format", choices=FORMATS, default="claude", help="hook event format the guard speaks")
    ap.add_argument("--guard-version", help="recorded as-is; default: output of `<guard> version`, else unknown")
    ap.add_argument("--config-label", default="default", help="free text describing the guard configuration")
    ap.add_argument("--coverage", choices=COVERAGES, help="default: context-aware with --guard, command otherwise")
    ap.add_argument("--probes", action="store_true", help="after the pack, send fail-open probes")
    ap.add_argument("--strict-probes", action="store_true", help="with --probes: any probe that proceeds fails the run")
    a = ap.parse_args(argv)
    if a.coverage is None:
        a.coverage = "context-aware" if a.guard else "command"
    return a


def main():
    a = parse_args()
    with open(os.path.join(PACK, "scenarios.json")) as f:
        pack = json.load(f)
    tmp = tempfile.mkdtemp(prefix="applygate-replay-")
    try:
        repo, plans, home = materialize(tmp)
        env = sandbox_env(tmp, home)
        version = guard_version(a, env, tmp)
        results = replay(a, pack, tmp, repo, plans, home, env)
        probes = run_probes(a, tmp, repo, plans, home, env) if a.probes else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    summary = summarize(a, pack, results, probes, version)
    print(json.dumps(summary))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"summary": summary, "results": results}, f, indent=1)
    if a.md:
        write_markdown(a.md, a, summary, results)

    ok = summary["exact"] == summary["total"]
    if a.strict_probes and probes is not None:
        ok = ok and summary["fail_open_count"] == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
