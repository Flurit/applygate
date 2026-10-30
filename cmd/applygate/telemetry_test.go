package main

import (
	"bytes"
	"strings"
	"testing"
)

const telemetryTrialLog = "../../review/agent-trial/results/2026-10-29-both/decisions.jsonl"

func TestTelemetryCommandsAndTheGuardAgainstAgentsSwitchingIt(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	t.Setenv("APPLYGATE_TELEMETRY", "")
	t.Setenv("DO_NOT_TRACK", "")
	var out, errb bytes.Buffer
	if code := run([]string{"telemetry", "status", "--log", telemetryTrialLog}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "telemetry: off") || !strings.Contains(out.String(), "next report: 169 decisions") {
		t.Fatalf("status: exit %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"telemetry", "on"}, nil, &out, &errb); code != 1 || !strings.Contains(errb.String(), "no endpoint") {
		t.Fatalf("on without an endpoint: exit %d, %s", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := run([]string{"telemetry", "on", "--endpoint", "http://127.0.0.1:9/v1"}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "telemetry on") {
		t.Fatalf("on: exit %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"telemetry", "send", "--dry-run", "--log", telemetryTrialLog}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), `"schema": 1`) || strings.Contains(out.String(), "/work") {
		t.Fatalf("dry run: exit %d\n%s", code, out.String())
	}
	out.Reset()
	errb.Reset()
	// An agent may not flip the switch: both directions are guard tampering.
	for _, cmd := range []string{"applygate telemetry on --endpoint https://x.example/v1", "applygate telemetry off"} {
		if code := run([]string{"check", "--cwd", t.TempDir(), cmd}, nil, &out, &errb); code != 3 || !strings.Contains(out.String(), "guard-tampering") {
			t.Fatalf("%q: exit %d\n%s", cmd, code, out.String())
		}
		out.Reset()
	}
	if code := run([]string{"check", "--cwd", t.TempDir(), "applygate telemetry status"}, nil, &out, &errb); code != 0 {
		t.Fatalf("reading the status is harmless: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"telemetry", "off"}, nil, &out, &errb); code != 0 || !strings.Contains(out.String(), "telemetry off") {
		t.Fatalf("off: exit %d\n%s", code, out.String())
	}
}
