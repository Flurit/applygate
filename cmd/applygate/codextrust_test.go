package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The bytes Codex hashes for a hook entry, as codex-rs builds them
// (hook_hash, version_for_toml): event, matcher and the normalized handler,
// keys sorted, no spaces, the default timeout filled in.
func TestCodexHookPreimage(t *testing.T) {
	star := "*"
	cases := []struct {
		matcher *string
		handler map[string]any
		want    string
	}{
		{&star, map[string]any{"type": "command", "command": `"/usr/local/bin/applygate" hook codex`, "timeout": 30.0},
			`{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"\"/usr/local/bin/applygate\" hook codex","timeout":30,"type":"command"}],"matcher":"*"}`},
		{nil, map[string]any{"type": "command", "command": "applygate hook codex <&>", "statusMessage": "checking", "additionalContextLimit": 2500.0},
			`{"event_name":"pre_tool_use","hooks":[{"async":false,"command":"applygate hook codex <&>","statusMessage":"checking","timeout":600,"type":"command"}]}`},
	}
	for _, c := range cases {
		got, ok := codexHookPreimage(c.matcher, c.handler)
		if !ok || string(got) != c.want {
			t.Errorf("preimage:\n got %s\nwant %s", got, c.want)
		}
	}
	if _, ok := codexHookPreimage(&star, map[string]any{"type": "prompt"}); ok {
		t.Error("a non-command handler has a command preimage")
	}
	// Known answer: the trusted_hash Codex 0.166.0 itself stored (macOS,
	// 2026-10-30) after /hooks for the entry applygate's installer wrote.
	got, _ := codexHookHash(&star, map[string]any{"type": "command", "command": `"/Users/apple/.local/bin/applygate" hook codex`, "timeout": 30.0})
	if want := "sha256:bc391f7b81abc07f0eebc11b60632e65b02f54d956b7e46cf44389559ac86ade"; got != want {
		t.Errorf("hash %s, want Codex's %s", got, want)
	}
	// Known answer: Codex 0.166.0 (2026-11-11), a command with quotes and an
	// env prefix, as the live re-test fixture's hook has.
	env := `/usr/bin/env XDG_CONFIG_HOME=/private/tmp/ag-retest/xdg/config XDG_STATE_HOME=/private/tmp/ag-retest/xdg/state "/private/tmp/ag-retest/bin/applygate" hook codex`
	got, _ = codexHookHash(&star, map[string]any{"type": "command", "command": env, "timeout": 30.0})
	if want := "sha256:6ae3a5ef691a6d2ce70db2e2de33bacf25a7cce88a37c006d8466326fce05139"; got != want {
		t.Errorf("env-prefixed hash %s, want Codex's %s", got, want)
	}
}

// doctor says whether Codex will run each applygate handler: trusted when the
// stored hash matches, modified after a reinstall changed it, untrusted with
// no entry, disabled when turned off.
func TestCodexHookTrust(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".codex", "hooks.json")
	os.MkdirAll(filepath.Dir(path), 0o755)
	hooks := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"\"/usr/local/bin/applygate\" hook codex","timeout":30}]}]}}`)
	os.WriteFile(path, hooks, 0o644)
	star := "*"
	hash, _ := codexHookHash(&star, map[string]any{"type": "command", "command": `"/usr/local/bin/applygate" hook codex`, "timeout": 30.0})
	key := path + ":pre_tool_use:0:0"
	for _, c := range []struct{ toml, want string }{
		{"[hooks.state]\n\n[hooks.state.\"" + key + "\"]\ntrusted_hash = \"" + hash + "\"\n", "trusted"},
		{"[hooks.state.\"" + key + "\"]\ntrusted_hash = \"sha256:old\"\n", "modified"},
		{"[hooks.state.\"" + key + "\"]\nenabled = false\ntrusted_hash = \"" + hash + "\"\n", "disabled"},
		{"[hooks.state]\n\"" + key + "\" = { trusted_hash = \"" + hash + "\" }\n", "trusted"},
		{"[hooks.state.'" + key + "']\ntrusted_hash = \"" + hash + "\"\n", "trusted"},
		{"[hooks.state.\"/elsewhere/.codex/hooks.json:pre_tool_use:0:0\"]\ntrusted_hash = \"" + hash + "\"\n", "untrusted"},
		{"", "untrusted"},
	} {
		got := codexHookTrust(path, hooks, []byte(c.toml))
		if len(got) != 1 || got[0].State != c.want {
			t.Errorf("config.toml %q: %+v, want %s", c.toml, got, c.want)
		}
	}
	// An entry that is not applygate's is not reported.
	other := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/other-hook"}]}]}}`)
	if got := codexHookTrust(path, other, nil); len(got) != 0 {
		t.Errorf("other hook reported: %+v", got)
	}
}
