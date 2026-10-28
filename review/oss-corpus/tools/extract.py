#!/usr/bin/env python3
"""Extract commands an agent could plausibly run from a cloned repository.

Reads files only; never executes anything. Sources:
  - fenced code blocks in Markdown (bash/sh/shell/console/zsh/untagged)
  - `run:` steps in GitHub Actions workflows
  - Makefile targets (replayed as `make <target>` in the Makefile's directory)
  - shell scripts (replayed as `./path/script.sh` from the repo root)
Output: JSON Lines with repo, source, line, kind, cwd (relative), command.
"""
import json
import os
import re
import sys

SHELL_LANGS = {"", "bash", "sh", "shell", "console", "zsh", "shell-session", "shellsession", "terminal"}
SKIP_DIRS = {".git", "node_modules", ".terraform", "vendor"}


def norm_cwd(root, d):
    rel = os.path.relpath(d, root)
    return "" if rel == "." else rel


def md_blocks(path):
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r"^\s*(```|~~~)\s*([\w+-]*)", lines[i])
        if not m:
            i += 1
            continue
        fence, lang = m.group(1), m.group(2).lower()
        start = i + 1
        j = start
        while j < len(lines) and not lines[j].strip().startswith(fence):
            j += 1
        if lang in SHELL_LANGS:
            yield start + 1, lang, lines[start:j]
        i = j + 1


def logical_lines(body, console):
    """Join backslash continuations; strip prompts; drop comments/output."""
    out, buf, first = [], "", None
    for n, raw in enumerate(body):
        line = raw.rstrip()
        if console or re.match(r"^\s*\$ ", line):
            m = re.match(r"^\s*[$#>] (.*)$", line) if console else re.match(r"^\s*\$ (.*)$", line)
            if not m and not buf:
                continue  # console output line
            if m and not buf:
                line = m.group(1)
        if not buf:
            first = n
            s = line.strip()
            if not s or s.startswith("#"):
                continue
        buf = (buf + " " + line.strip()) if buf else line.strip()
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
            continue
        out.append((first, buf))
        buf = ""
    if buf:
        out.append((first, buf))
    return out


def workflow_runs(path):
    """Minimal parser for `run:` steps (handles `run: |` blocks)."""
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(-\s+)?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
        rest = m.group(3).strip()
        wd = ""
        # look a few lines around for working-directory in the same step
        for k in range(max(0, i - 6), min(len(lines), i + 30)):
            w = re.match(r"^\s*(-\s+)?working-directory:\s*(.+)$", lines[k])
            if w:
                wd = w.group(2).strip().strip("'\"")
                break
        if rest in ("|", ">", "|-", ">-") or rest.startswith("|") or rest.startswith(">"):
            body, j = [], i + 1
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
                body.append(lines[j])
                j += 1
            yield i + 1, wd, "\n".join(b.strip() for b in body).strip()
            i = j
        else:
            if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in "'\"":
                rest = rest[1:-1]  # YAML-quoted scalar
            yield i + 1, wd, rest
            i += 1


def make_targets(path):
    for n, line in enumerate(open(path, encoding="utf-8", errors="replace"), 1):
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.\-/]*)\s*:(?!=)", line)
        if m and not m.group(1).startswith("."):
            yield n, m.group(1)


def main():
    repo_root, name = sys.argv[1], sys.argv[2]
    seen = set()

    def emit(src, line, kind, cwd, cmd):
        cmd = cmd.strip()
        if not cmd or len(cmd) > 4000:
            return
        key = (cwd, cmd)
        if key in seen:
            return
        seen.add(key)
        print(json.dumps({"repo": name, "source": src, "line": line, "kind": kind, "cwd": cwd, "command": cmd}))

    for d, dirs, files in os.walk(repo_root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, repo_root)
            if f.lower().endswith(".md"):
                for start, lang, body in md_blocks(p):
                    cwd = norm_cwd(repo_root, d)
                    for off, cmd in logical_lines(body, lang in ("console", "shell-session", "shellsession", "terminal")):
                        emit(rel, start + off, "markdown", cwd, cmd)
                        # Later lines of the block run where an earlier `cd` left them.
                        m = re.match(r"^cd\s+([^\s;&|$`]+)\s*$", cmd)
                        if m and not m.group(1).startswith(("~", "-", "/")):
                            nxt = os.path.normpath(os.path.join(cwd, m.group(1)))
                            if not nxt.startswith(".."):
                                cwd = "" if nxt == "." else nxt
            elif rel.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")):
                for line, wd, body in workflow_runs(p):
                    # GitHub substitutes ${{ ... }} before the shell runs; a
                    # placeholder keeps the shell syntax intact.
                    body = re.sub(r"\$\{\{[^}]*\}\}", "GHA_EXPR", body)
                    emit(rel, line, "workflow", wd.lstrip("./") if wd and "${{" not in wd else "", body)
            elif f in ("Makefile", "makefile", "GNUmakefile"):
                for line, t in make_targets(p):
                    emit(rel, line, "make", norm_cwd(repo_root, d), "make " + t)
            elif f.endswith(".sh"):
                emit(rel, 1, "script", "", "./" + rel)


if __name__ == "__main__":
    main()
