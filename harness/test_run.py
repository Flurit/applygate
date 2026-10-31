#!/usr/bin/env python3
"""Unit tests for harness/run.py scoring. Run: python3 -I harness/test_run.py

They never start a guard that executes anything: the end-to-end test uses a
tiny fake guard script that only prints a fixed response.
"""
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("run", os.path.join(HERE, "run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

D80 = {"id": "D80", "kind": "dangerous", "expect": ["block"],
       "must_mention": ["tier protected", "backend s3://acme-prod-tfstate/app/terraform.tfstate looks like production"]}
B13 = {"id": "B13", "kind": "benign", "expect": ["allow"]}
CONFIG_ERROR = ("applygate: config error: .applygate.yaml: yaml: unmarshal errors:\n"
                "  line 27: field wrappers not found in type config.Config (applygate fails closed here; ...)\n")


class Judge(unittest.TestCase):
    def test_applygate_fail_closed_is_never_a_pass(self):
        # v0.1.2 replaying a pack whose fixture config it cannot parse.
        v, ok, missing = run.judge(D80, "block", CONFIG_ERROR, 2, applygate=True)
        self.assertEqual((v, ok), (run.FAIL_CLOSED, False))
        v, ok, _ = run.judge(B13, "block", CONFIG_ERROR, 2, applygate=True)
        self.assertEqual((v, ok), (run.FAIL_CLOSED, False))

    def test_applygate_needs_the_expected_reason(self):
        v, ok, missing = run.judge(D80, "block", "applygate: BLOCK.\n- [block] destroy: tier standard", 0, applygate=True)
        self.assertEqual((v, ok), ("block", False))
        self.assertEqual(missing, D80["must_mention"])
        msg = "applygate: BLOCK. environment: prod (tier protected; backend s3://acme-prod-tfstate/app/terraform.tfstate looks like production)"
        self.assertEqual(run.judge(D80, "block", msg, 0, applygate=True), ("block", True, []))

    def test_other_guards_keep_exit_2_as_block_and_skip_mentions(self):
        self.assertEqual(run.judge(D80, "block", "denied", 2, applygate=False), ("block", True, []))

    def test_host_that_cannot_ask_expects_block(self):
        d42 = {"id": "D42", "kind": "dangerous", "expect": ["ask"], "must_mention": ["tier standard"]}
        self.assertEqual(run.judge(d42, "block", "applygate: BLOCK. tier standard", 0, applygate=True, fmt="cline"), ("block", True, []))
        self.assertEqual(run.judge(d42, "block", "tier standard", 0, applygate=True, fmt="claude")[:2], ("block", False))
        self.assertEqual(run.judge(d42, "ask", "tier standard", 0, applygate=True, fmt="copilot")[:2], ("ask", True))

    def test_unconfirmed_directory_may_be_stricter_never_weaker(self):
        self.assertEqual(run.judge(B13, "block", "tier protected", 0, applygate=True, fmt="windsurf"), ("block", True, []))
        self.assertEqual(run.judge(D80, "allow", "", 0, applygate=True, fmt="windsurf")[:2], ("allow", False))
        self.assertEqual(run.judge(B13, "block", "tier protected", 0, applygate=True, fmt="gemini")[:2], ("block", False))

    def test_exit2_formats_block_with_exit_2_and_still_detect_fail_closed(self):
        d01 = {"id": "D01", "kind": "dangerous", "expect": ["block"]}
        self.assertEqual(run.judge(d01, "block", "applygate: BLOCK.", 2, applygate=True, fmt="opencode"), ("block", True, []))
        self.assertEqual(run.judge(D80, "block", CONFIG_ERROR, 2, applygate=True, fmt="opencode")[:2], (run.FAIL_CLOSED, False))
        self.assertEqual(run.judge(D80, "block", CONFIG_ERROR, 0, applygate=True, fmt="cline")[:2], (run.FAIL_CLOSED, False))

    def test_timeout_is_an_error(self):
        self.assertEqual(run.judge(D80, "timeout", "timeout", None, applygate=True)[:2], ("error", False))


class EndToEnd(unittest.TestCase):
    """replay() with a fake applygate that always fails closed: nothing may pass."""

    def test_fail_closed_guard_scores_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "fake-applygate")
            with open(fake, "w") as f:
                f.write("#!/bin/sh\ncat >/dev/null\necho 'applygate: config error: bad config (applygate fails closed here)' >&2\nexit 2\n")
            os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
            out = os.path.join(tmp, "r.json")
            p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "run.py"), "--guard", fake, "--json", out],
                               capture_output=True, text=True, timeout=300)
            self.assertEqual(p.returncode, 1, p.stderr)
            s = json.load(open(out))["summary"]
            self.assertEqual(s["exact"], 0)
            self.assertEqual(s["dangerous_caught"], 0)
            self.assertEqual(s["fail_closed"], s["total"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
