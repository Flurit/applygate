#!/usr/bin/env python3
"""Render the README demo (docs/assets/demo.svg) from real `applygate check` output.

Runs each command against a copy of the scenario-pack fixture repository and
writes an animated SVG terminal: lines appear in order and commands are typed
out. Nothing is executed except `applygate check`, which only judges the
command string. Without CSS animation (or with reduced motion) the SVG shows
the final frame.

    go build -o bin/applygate ./cmd/applygate
    python3 -I scripts/demo.py bin/applygate > docs/assets/demo.svg
"""
import html
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "harness", "pack", "fixtures", "repo")
SHOWN_DIR = "~/acme-infra"

SCENES = [
    ("An agent tries to destroy production", "terraform -chdir=envs/prod destroy -auto-approve"),
    ("The same command hidden in base64",
     "echo dGVycmFmb3JtIC1jaGRpcj1lbnZzL3Byb2QgZGVzdHJveSAtYXV0by1hcHByb3Zl | base64 -d | sh"),
    ("Text that only mentions it", 'git commit -m "never run terraform destroy"'),
    ("Read-only work goes through", "terraform -chdir=envs/prod plan"),
]

COLS, CW, LH, PAD, BAR = 100, 7.8, 19, 18, 34
BG = "#0d1117"
COLOR = {
    "dim": "#8b949e", "dir": "#39c5cf", "fg": "#e6edf3", "body": "#c9d1d9",
    "block": "#ff7b72", "ask": "#e3b341", "allow": "#3fb950", "next": "#e3b341",
}
TYPE_SPEED = 0.028  # seconds per typed character


def run_scenes(binary):
    """Yield (caption, command, verdict, body lines) from real applygate output."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = os.path.join(tmp, "acme-infra")
        shutil.copytree(FIXTURE, repo, symlinks=True)
        for caption, cmd in SCENES:
            out = subprocess.run([binary, "check", cmd], cwd=repo, capture_output=True, text=True).stdout
            out = out.replace(os.path.realpath(repo), SHOWN_DIR).replace(repo, SHOWN_DIR)
            verdict, *body = out.rstrip("\n").split("\n")
            yield caption, cmd, verdict, body


def wrap(text, indent_extra=2):
    indent = " " * (len(text) - len(text.lstrip()) + indent_extra)
    return textwrap.wrap(text, COLS, subsequent_indent=indent, break_on_hyphens=False) or [""]


def build_rows(binary):
    """Rows of (segments, appear_time, typing) where segments are (text, color)."""
    rows, t = [], 0.6
    prompt = [(SHOWN_DIR, "dir"), (" $ ", "fg")]
    plen = len(SHOWN_DIR) + 3
    for i, (caption, cmd, verdict, body) in enumerate(run_scenes(binary)):
        if i:
            rows.append(([("", "fg")], t, None))
        rows.append(([(f"# {caption}", "dim")], t, None))
        t += 0.4
        typed = f"applygate check '{cmd}'"
        first, rest = typed[: COLS - plen], typed[COLS - plen:]
        rows.append((prompt + [(first, "fg")], t, (plen, len(first), t)))
        t += len(first) * TYPE_SPEED
        for chunk in textwrap.wrap(rest, COLS) if rest else []:
            rows.append(([(chunk, "fg")], t, (0, len(chunk), t)))
            t += len(chunk) * TYPE_SPEED
        t += 0.5
        rows.append(([(verdict, verdict)], t, None))
        for line in body:
            if line.startswith("Next step:"):
                parts = wrap(line, 0)
                rows.append(([("Next step:", "next"), (parts[0][len("Next step:"):], "body")], t, None))
                rows.extend(([(p, "body")], t, None) for p in parts[1:])
            elif line.startswith("applygate: "):
                rows.append(([(line, verdict)], t, None))
            else:
                rows.extend(([(p, "body")], t, None) for p in wrap(line))
        t += 2.6 if body else 1.2
    rows.append((prompt + [("█", "dim")], t, "cursor"))
    return rows, t + 3.5


def render(rows, total):
    width = round(COLS * CW + 2 * PAD)
    height = round(BAR + PAD + len(rows) * LH + PAD / 2)
    pct = lambda s: f"{100 * s / total:.3f}"
    css = [
        f"text{{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;white-space:pre}}",
        "@media (prefers-reduced-motion:reduce){*{animation:none!important}}",
    ]
    body = []
    for i, (segs, at, typing) in enumerate(rows):
        y = BAR + PAD + i * LH
        length = sum(len(s) for s, _ in segs)
        spans = "".join(f'<tspan fill="{COLOR[c]}">{html.escape(s)}</tspan>' for s, c in segs)
        fit = f' textLength="{length * CW:.1f}" lengthAdjust="spacingAndGlyphs"' if length else ""
        body.append(f'<text class="r{i}" x="{PAD}" y="{y}"{fit}>{spans}</text>')
        css.append(f".r{i}{{animation:r{i} {total:.2f}s linear infinite}}"
                   f"@keyframes r{i}{{0%,{pct(at)}%{{opacity:0}}{pct(at + 0.01)}%,97%{{opacity:1}}100%{{opacity:0}}}}")
        if typing == "cursor":
            css.append(f".r{i} tspan:last-child{{animation:blink 1s steps(1) infinite}}")
        elif typing:
            col, n, start = typing
            end, shift = start + n * TYPE_SPEED, (n + 1) * CW
            body.append(f'<rect class="o{i}" x="{PAD + col * CW:.1f}" y="{y - LH + 5}" width="{shift:.1f}" '
                        f'height="{LH}" fill="{BG}" opacity="0"/>')
            css.append(f".o{i}{{animation:o{i} {total:.2f}s linear infinite}}"
                       f"@keyframes o{i}{{0%,{pct(start)}%{{opacity:1;transform:translateX(0);animation-timing-function:steps({n},end)}}"
                       f"{pct(end)}%{{opacity:1;transform:translateX({shift:.1f}px)}}"
                       f"{pct(end + 0.01)}%,100%{{opacity:0;transform:translateX({shift:.1f}px)}}}}")
    css.append("@keyframes blink{50%{opacity:0}}")
    dots = "".join(f'<circle cx="{PAD + 6 + k * 20}" cy="{BAR / 2}" r="6" fill="{c}"/>'
                   for k, c in enumerate(["#ff5f57", "#febc2e", "#28c840"]))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
            f'role="img" aria-label="applygate check blocks terraform destroy in prod, also hidden in base64, '
            f'and allows a commit message that mentions it">\n'
            f'<style>{"".join(css)}</style>\n'
            f'<rect width="{width}" height="{height}" rx="10" fill="{BG}"/>\n'
            f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="10" fill="none" stroke="#30363d"/>\n'
            f'{dots}\n' + "\n".join(body) + "\n</svg>\n")


def main():
    rows, total = build_rows(os.path.abspath(sys.argv[1]))
    sys.stdout.write(render(rows, total))


if __name__ == "__main__":
    main()
