#!/usr/bin/env python3
"""Replay a command corpus through `applygate check`. Never executes the commands.

applygate runs with an empty PATH (so terraform, aws and git cannot be found or
started), a fake HOME and an empty user config, and only reads files.
Usage: replay.py APPLYGATE_BIN REPOS_DIR CORPUS.jsonl OUT.jsonl LABEL
"""
import json
import os
import subprocess
import sys
import tempfile

applygate, repos, corpus, out, label = sys.argv[1:6]
home = tempfile.mkdtemp(prefix="sb-home-")
env = {"HOME": home, "PATH": "/nonexistent", "XDG_CONFIG_HOME": os.path.join(home, "cfg"),
       "XDG_STATE_HOME": os.path.join(home, "state"), "LANG": "C.UTF-8"}
with open(corpus) as f, open(out, "w") as w:
    for line in f:
        r = json.loads(line)
        cwd = os.path.join(repos, r["repo"], r["cwd"])
        p = subprocess.run([applygate, "check", "--json", "--cwd", cwd, "--", r["command"]],
                           capture_output=True, text=True, env=env, timeout=30, shell=False)
        try:
            d = json.loads(p.stdout)
        except json.JSONDecodeError:
            r.update(label=label, verdict="error", error=(p.stderr or p.stdout)[:300])
            w.write(json.dumps(r) + "\n")
            continue
        acts = [a for a in d.get("actions") or [] if a.get("verdict") != "allow"]
        # Keep results free of the local work directory: paths become repo-relative.
        strip = lambda t: (t or "").replace(os.path.join(repos, ""), "")
        r.update(label=label, verdict=d["enforced"], actions=[{
            "class": a["class"], "tier": a.get("tier", ""), "env": a.get("environment", ""),
            "why": strip(a.get("why")), "command": strip(a.get("command")),
            "findings": [f["rule"] for f in a.get("findings") or [] if f.get("severity") != "info"],
        } for a in acts])
        w.write(json.dumps(r) + "\n")
