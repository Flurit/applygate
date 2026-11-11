package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Codex runs a hook from a hooks.json only after a person reviewed it with
// /hooks, which stores the hook's hash under [hooks.state."KEY"] in
// $CODEX_HOME/config.toml. A hook with no stored hash, or whose entry changed
// since (a reinstall writes a new entry), is skipped without a message, so
// the session runs unguarded while the file still holds the hook. doctor
// recomputes Codex's hash to say which.
//
// The hash follows codex-rs at rust-v0.166.0: hooks/src/engine/discovery.rs
// (hook_hash, the normalized handler), config/src/fingerprint.rs
// (version_for_toml: SHA-256 of the identity as JSON with sorted keys) and
// hooks/src/lib.rs (hook_key).

// codexHookStatus is what Codex will do with one applygate handler.
type codexHookStatus struct {
	Key   string
	State string // "trusted", "untrusted", "modified" or "disabled"
}

// codexDefaultContextLimit is Codex's default additionalContextLimit; a value
// equal to it is left out of the hash.
const codexDefaultContextLimit = 2500

// codexHookHash is Codex's trusted_hash for one PreToolUse command handler of
// a matcher group.
func codexHookHash(matcher *string, handler map[string]any) (string, bool) {
	pre, ok := codexHookPreimage(matcher, handler)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256(pre)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

// codexHookPreimage is the JSON Codex hashes for one handler: the normalized
// identity {event_name, matcher, hooks: [handler]} with sorted keys.
func codexHookPreimage(matcher *string, handler map[string]any) ([]byte, bool) {
	command, _ := handler["command"].(string)
	if typ, _ := handler["type"].(string); typ != "command" || strings.TrimSpace(command) == "" {
		return nil, false
	}
	timeout := int64(600)
	if t, ok := handler["timeout"].(float64); ok {
		timeout = int64(t)
	}
	if timeout < 1 {
		timeout = 1
	}
	async, _ := handler["async"].(bool)
	h := map[string]any{"type": "command", "command": command, "timeout": timeout, "async": async}
	if s, ok := handler["statusMessage"].(string); ok {
		h["statusMessage"] = s
	}
	if l, ok := handler["additionalContextLimit"].(float64); ok && int64(l) != codexDefaultContextLimit {
		h["additionalContextLimit"] = int64(l)
	}
	identity := map[string]any{"event_name": "pre_tool_use", "hooks": []any{h}}
	if matcher != nil {
		identity["matcher"] = *matcher
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // serde_json does not escape <, > or &
	if enc.Encode(identity) != nil {
		return nil, false
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	// serde_json writes U+2028 and U+2029 as they are; Go escapes them.
	out = bytes.ReplaceAll(out, []byte(` `), []byte(" "))
	out = bytes.ReplaceAll(out, []byte(` `), []byte(" "))
	return out, true
}

// codexHookStates reads the [hooks.state."KEY"] tables of a Codex
// config.toml: the stored hash and the enabled switch of each key. It reads
// only that shape (the one Codex's /hooks writes) and the inline form
// "KEY" = { trusted_hash = "…" } under [hooks.state]; anything else is not
// found, which doctor reports as not trusted.
func codexHookStates(toml []byte) map[string]codexState {
	out := map[string]codexState{}
	header := regexp.MustCompile(`^\[\s*hooks\.state\.("(?:[^"\\]|\\.)*"|'[^']*')\s*\]\s*(?:#.*)?$`)
	inline := regexp.MustCompile(`^("(?:[^"\\]|\\.)*"|'[^']*')\s*=\s*\{(.*)\}\s*(?:#.*)?$`)
	hashRe := regexp.MustCompile(`(?:^|[\s,{])trusted_hash\s*=\s*"([^"]*)"`)
	enabledRe := regexp.MustCompile(`(?:^|[\s,{])enabled\s*=\s*(true|false)`)
	cur, inState := "", false
	sc := bufio.NewScanner(bytes.NewReader(toml))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			cur, inState = "", false
			if m := header.FindStringSubmatch(line); m != nil {
				cur = tomlKey(m[1])
			} else if regexp.MustCompile(`^\[\s*hooks\.state\s*\]`).MatchString(line) {
				inState = true
			}
			continue
		}
		apply := func(key, body string) {
			st := out[key]
			if m := hashRe.FindStringSubmatch(body); m != nil {
				st.hash = m[1]
			}
			if m := enabledRe.FindStringSubmatch(body); m != nil {
				st.disabled = m[1] == "false"
			}
			out[key] = st
		}
		switch {
		case cur != "":
			apply(cur, line)
		case inState:
			if m := inline.FindStringSubmatch(line); m != nil {
				apply(tomlKey(m[1]), m[2])
			}
		}
	}
	return out
}

type codexState struct {
	hash     string
	disabled bool
}

// tomlKey unquotes a TOML basic or literal string key.
func tomlKey(q string) string {
	if strings.HasPrefix(q, "'") {
		return strings.Trim(q, "'")
	}
	if s, err := strconv.Unquote(q); err == nil {
		return s
	}
	return strings.Trim(q, `"`)
}

// codexHookTrust reports what Codex will do with each applygate handler in
// the hooks.json at path, given the user's Codex config.toml.
func codexHookTrust(path string, hooksJSON, configTOML []byte) []codexHookStatus {
	var doc struct {
		Hooks map[string][]struct {
			Matcher *string          `json:"matcher"`
			Hooks   []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(hooksJSON, &doc) != nil {
		return nil
	}
	states := codexHookStates(configTOML)
	// Codex keys a hook by the path it loaded the file from; the project file
	// is found from the session's directory, which may be written with or
	// without symlinks resolved (/tmp, /private/tmp).
	sources := []string{path}
	if abs, err := filepath.Abs(path); err == nil && abs != path {
		sources = append(sources, abs)
	}
	if real, err := filepath.EvalSymlinks(path); err == nil && !contains(sources, real) {
		sources = append(sources, real)
	}
	var out []codexHookStatus
	for g, group := range doc.Hooks["PreToolUse"] {
		for h, handler := range group.Hooks {
			command, _ := handler["command"].(string)
			if !isApplygateEntry(map[string]any{"command": command}) {
				continue
			}
			want, ok := codexHookHash(group.Matcher, handler)
			st := codexHookStatus{Key: sources[0] + ":pre_tool_use:" + strconv.Itoa(g) + ":" + strconv.Itoa(h), State: "untrusted"}
			for _, src := range sources {
				key := src + ":pre_tool_use:" + strconv.Itoa(g) + ":" + strconv.Itoa(h)
				s, found := states[key]
				if !found {
					continue
				}
				st.Key = key
				switch {
				case s.disabled:
					st.State = "disabled"
				case s.hash == "":
					st.State = "untrusted"
				case ok && s.hash == want:
					st.State = "trusted"
				default:
					st.State = "modified"
				}
				break
			}
			out = append(out, st)
		}
	}
	return out
}

// codexConfigPath is the user's Codex config.toml.
func codexConfigPath() string {
	if d := os.Getenv("CODEX_HOME"); d != "" {
		return filepath.Join(d, "config.toml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".codex", "config.toml")
}
