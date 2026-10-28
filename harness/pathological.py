#!/usr/bin/env python3
"""Pathological-input timing for seatbelt check (independent review, Task 4).

Each case is a synthetic command string or file; nothing is executed. We invoke
`seatbelt check` once per case (black box, one process incl. start-up) and record
wall time and peak RSS. Targets from the spec: 50 ms (command) and 1 s (plan).
"""
import json, os, resource, subprocess, sys, tempfile, time

GUARD = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "bin/seatbelt")


def run(cmd, cwd, files=None, symlinks=None, timeout=40):
    tmp = tempfile.mkdtemp(prefix="sbpath-")
    repo = os.path.join(tmp, "repo")
    os.makedirs(os.path.join(repo, "envs", "prod"))
    with open(os.path.join(repo, ".seatbelt.yaml"), "w") as f:
        f.write("version: 1\nmode: enforce\nstrict: true\n"
                "environments:\n  - {name: prod, tier: protected, match: {paths: [\"**\"]}}\n")
    with open(os.path.join(repo, "envs", "prod", "main.tf"), "w") as f:
        f.write('resource "terraform_data" "x" {}\n')
    for rel, content in (files or {}).items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
    for rel, target in (symlinks or {}).items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        os.symlink(target, p)
    env = {"HOME": os.path.join(tmp, "home"), "PATH": "/nonexistent", "USER": "a",
           "AWS_CONFIG_FILE": "/dev/null", "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
           "XDG_STATE_HOME": tmp + "/s", "XDG_CONFIG_HOME": tmp + "/c"}
    os.makedirs(env["HOME"])
    argv = [GUARD, "check", "--cwd", os.path.join(repo, cwd), cmd]
    t0 = time.perf_counter()
    try:
        before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=timeout, cwd=tmp)
        after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        ms = (time.perf_counter() - t0) * 1000
        rc = proc.returncode
        rss_kb = max(0, after - before)
    except subprocess.TimeoutExpired:
        ms, rc, rss_kb = timeout * 1000, "timeout", 0
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    return round(ms, 1), rc, rss_kb


def planrun(plan_json, tier="protected", timeout=40):
    tmp = tempfile.mkdtemp(prefix="sbplan-")
    p = os.path.join(tmp, "plan.json")
    with open(p, "w") as f:
        f.write(plan_json)
    env = {"HOME": tmp + "/h", "PATH": "/nonexistent"}
    os.makedirs(env["HOME"])
    t0 = time.perf_counter()
    try:
        before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        proc = subprocess.run([GUARD, "plan-check", "--tier", tier, p], capture_output=True, text=True,
                              env=env, timeout=timeout, cwd=tmp)
        after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        ms = (time.perf_counter() - t0) * 1000
        rc, rss_kb = proc.returncode, max(0, after - before)
    except subprocess.TimeoutExpired:
        ms, rc, rss_kb = timeout * 1000, "timeout", 0
    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    return round(ms, 1), rc, rss_kb


cases = []
# 1. very long command: 200k-char single argument
cases.append(("long_arg_200k", lambda: run("terraform plan " + "a" * 200000, "envs/prod")))
# 2. very long command: many chained segments
cases.append(("chained_20k", lambda: run(" && ".join(["true"] * 20000), "envs/prod")))
# 3. deeply nested command substitution
cases.append(("nested_subst_5k", lambda: run("echo " + "$(" * 5000 + "x" + ")" * 5000, "envs/prod")))
# 4. deeply nested quoting / braces
cases.append(("nested_braces_5k", lambda: run("echo " + "{" * 5000 + "a" + "}" * 5000, "envs/prod")))
# 5. huge here-doc piped to sh
cases.append(("heredoc_500k", lambda: run("cat <<EOF | sh\n" + ("echo line\n" * 50000) + "EOF", "envs/prod")))
# 6. many pipes
cases.append(("pipes_10k", lambda: run("echo x" + " | cat" * 10000, "envs/prod")))
# 7. deeply nested bash -c wrappers
cases.append(("bashc_nest", lambda: run("bash -c " + "'bash -c " * 0 + '"' + "terraform destroy" + '"', "envs/prod")))
# 8. large Makefile reached via make
big_mk = ".PHONY: destroy\n" + "".join(f"t{i}:\n\techo {i}\n" for i in range(20000)) + "destroy:\n\tterraform destroy -auto-approve\n"
cases.append(("make_big_20k_targets", lambda: run("make destroy", "envs/prod", files={"envs/prod/Makefile": big_mk})))
# 9. large shell script invoked
big_sh = "#!/bin/sh\n" + "echo x\n" * 100000 + "terraform destroy -auto-approve\n"
cases.append(("script_100k_lines", lambda: run("sh ./run.sh", "envs/prod", files={"envs/prod/run.sh": big_sh})))
# 10. symlink loop for a config/script path
cases.append(("symlink_loop", lambda: run("sh ./loop.sh", "envs/prod",
             symlinks={"envs/prod/loop.sh": "loop.sh"})))
# 11. many variable assignments then use
cases.append(("many_vars_10k", lambda: run("; ".join(f"v{i}=x" for i in range(10000)) + "; terraform destroy", "envs/prod")))
# 12. deeply nested functions
cases.append(("nested_funcs", lambda: run("".join(f"f{i}(){{ f{i+1}; }}; " for i in range(2000)) + "f0", "envs/prod")))

results = []
for name, fn in cases:
    try:
        ms, rc, rss = fn()
    except Exception as e:
        ms, rc, rss = -1, "exc:" + str(e)[:60], 0
    results.append({"case": name, "ms": ms, "rc": rc, "rss_mb": round(rss / 1024, 1)})
    print(f"{name:28} {ms:>9} ms  rc={rc}  rss={round(rss/1024,1)} MB")

# 50 MB plan JSON for plan-check
print("--- plan-check ---")
res = {"type": "aws_instance", "values": {}}
# build a resource_changes array large enough to reach ~50 MB
one = {"address": "aws_s3_bucket.b", "type": "aws_s3_bucket", "change": {"actions": ["delete"], "before": {}, "after": None}}
import copy
arr = []
size = 0
i = 0
while size < 50 * 1024 * 1024:
    c = copy.deepcopy(one)
    c["address"] = f"aws_s3_bucket.b{i}"
    arr.append(c)
    i += 1
    if i % 1000 == 0:
        size = len(json.dumps({"resource_changes": arr}))
plan = json.dumps({"format_version": "1.2", "resource_changes": arr})
print(f"plan size: {round(len(plan)/1024/1024,1)} MB, {len(arr)} resource_changes")
ms, rc, rss = planrun(plan)
results.append({"case": "plan_50mb", "ms": ms, "rc": rc, "rss_mb": round(rss / 1024, 1)})
print(f"{'plan_50mb':28} {ms:>9} ms  rc={rc}  rss={round(rss/1024,1)} MB")

with open("review/results/pathological.json", "w") as f:
    json.dump(results, f, indent=1)
