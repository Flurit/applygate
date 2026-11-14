package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Flurit/applygate/internal/config"
)

// applygate doctor --boundary says which assurance level this machine
// reaches. The hook judges a call before it runs and can be wrong; what
// holds when it is wrong is a boundary the agent cannot reach: a root-owned
// install, credentials that cannot change production without a person, and
// a host sandbox. Each level adds a control that doctor checks itself; a
// control it cannot check (a CI apply path, state-bucket guards) counts only
// when the person attests to it in the user config, and is reported as
// attested, never as verified (docs/boundary.md).
//
//	L0  the hook only
//	L1  L0 + a managed, exclusive install (root-owned, no other hooks)
//	L2  L1 + audited credentials (AWS, kube, gcloud, az) with no destructive path without a person
//	L3  L2 + a host sandbox set by managed settings + attested CI apply and state guards

var assuranceLevels = []string{"L0", "L1", "L2", "L3"}

func levelNum(l string) int {
	for i, n := range assuranceLevels {
		if strings.EqualFold(l, n) {
			return i
		}
	}
	return -1
}

// attestable are the controls the config may vouch for.
var attestable = []string{"ci_apply", "state_guards", "oidc_pinned", "branch_protection"}

type boundaryCheck struct {
	level  int    // the level this check is part of
	status string // "ok", "FAIL", "attested", "not verified"
	text   string
}

// boundaryResult is every check and the level reached: the highest level
// whose checks (and those of the levels below) all hold.
type boundaryResult struct {
	checks  []boundaryCheck
	reached int
	// audited is false when the cloud was not asked (applygate scan without
	// --boundary): L2 then holds one check saying so.
	audited bool
	// What the credential audit found: credentials with no destructive path
	// to production without a person, credentials with one, and findings
	// that show neither (not checked, or in no environment the config names).
	credsOK, credsFail, credsUnclear int
}

func (r *boundaryResult) add(level int, status, format string, a ...any) {
	r.checks = append(r.checks, boundaryCheck{level, status, fmt.Sprintf(format, a...)})
}

func evalBoundary(cfg *config.Config) *boundaryResult { return evalBoundaryWith(cfg, true) }

// evalBoundaryWith makes the boundary checks. With audit false it makes only
// the ones that read this machine: the cloud and the clusters are not asked
// what the credentials can do, so L2 is not reached.
func evalBoundaryWith(cfg *config.Config, audit bool) *boundaryResult {
	r := &boundaryResult{audited: audit}

	// L1: managed and exclusive.
	if !config.Managed() {
		r.add(1, "not verified", "no managed install: the agent's user can change the hook, the config and the binary (sudo applygate install --managed --exclusive, docs/managed.md)")
	} else {
		bad := 0
		doctorManaged(func(ok bool, f string, a ...any) {
			if !ok {
				bad++
				r.add(1, "FAIL", f, a...)
			}
		})
		if bad == 0 {
			r.add(1, "ok", "managed install checked: system config, binary and Claude Code settings are root-owned and no other hooks run")
		}
	}

	// L2: credentials.
	if audit {
		for _, f := range auditAll(cfg) {
			switch f.level {
			case "ok":
				r.credsOK++
			case "FAIL":
				r.credsFail++
				r.add(2, "FAIL", "%s", f.text)
			default:
				r.credsUnclear++
				r.add(2, "not verified", "%s", f.text)
			}
		}
		if r.credsOK == 0 {
			r.add(2, "not verified", "no AWS profile, kube context, gcloud account or Azure subscription could be audited, so nothing shows the agent's credentials cannot change production")
		} else {
			r.add(2, "ok", "%d credential(s) audited with no destructive path without a person", r.credsOK)
		}
		for _, p := range credentialFiles() {
			r.add(2, "not verified", "%s is readable by this user, so is any agent that runs as you; the audit above covers what it can do, not who can read it", p)
		}
	} else {
		r.add(2, "not verified", "credentials not audited: nothing was asked of AWS, Google Cloud, Azure or the clusters")
		for _, p := range credentialFiles() {
			r.add(2, "not verified", "%s is readable by this user, so is any agent that runs as you", p)
		}
	}

	// L3: sandbox, and what only a person can vouch for.
	switch s, why := sandboxState(); s {
	case "managed":
		r.add(3, "ok", "%s", why)
	default:
		r.add(3, "not verified", "%s", why)
	}
	attested := map[string]bool{}
	for _, a := range cfg.Boundary.Attest {
		attested[strings.ToLower(a)] = true
	}
	for _, a := range cfg.Boundary.Attest {
		known := false
		for _, k := range attestable {
			known = known || strings.EqualFold(a, k)
		}
		if !known {
			r.add(3, "FAIL", "boundary.attest names %q, which is not one of %s", a, strings.Join(attestable, ", "))
		}
	}
	for _, k := range attestable {
		need := k == "ci_apply" || k == "state_guards"
		switch {
		case attested[k]:
			r.add(3, "attested", "%s (vouched for in the user config, not checked)", k)
		case need:
			r.add(3, "not verified", "%s is not attested: set boundary.attest in the user config once it is true", k)
		default:
			r.add(0, "not verified", "%s is not attested (optional)", k)
		}
	}

	r.reached = reachedLevel(r.checks)
	return r
}

// reachedLevel is the highest level whose checks, and those of every level
// below it, all hold. A check that is not ok or attested stops the climb.
func reachedLevel(checks []boundaryCheck) int {
	reached := 0
	for lvl := 1; lvl <= 3; lvl++ {
		n := 0
		for _, c := range checks {
			if c.level != lvl {
				continue
			}
			if n++; c.status != "ok" && c.status != "attested" {
				return reached
			}
		}
		if n == 0 {
			return reached // a level nothing was checked for is not reached
		}
		reached = lvl
	}
	return reached
}

// credentialFiles are the long-lived credential stores this user can read.
func credentialFiles() []string {
	h, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range []string{".aws/credentials", ".kube/config", ".config/gcloud/application_default_credentials.json", ".azure/accessTokens.json"} {
		f := filepath.Join(h, p)
		if fh, err := os.Open(f); err == nil {
			fh.Close()
			out = append(out, f)
		}
	}
	return out
}

// sandboxState reports whether Claude Code's sandbox is on with no escape
// hatch, and where that is set. Only managed settings count: the agent's
// user can change the others.
func sandboxState() (string, string) {
	var managed []string
	if config.ClaudeManagedDir != "" {
		managed = append(managed, filepath.Join(config.ClaudeManagedDir, "managed-settings.json"))
		if m, _ := filepath.Glob(filepath.Join(config.ClaudeManagedDir, "managed-settings.d", "*.json")); m != nil {
			managed = append(managed, m...)
		}
	}
	read := func(p string) (on, hatch bool, ok bool) {
		b, err := os.ReadFile(p)
		if err != nil {
			return false, false, false
		}
		var s struct {
			Sandbox struct {
				Enabled                  *bool `json:"enabled"`
				AllowUnsandboxedCommands *bool `json:"allowUnsandboxedCommands"`
			} `json:"sandbox"`
		}
		if json.Unmarshal(b, &s) != nil {
			return false, false, false
		}
		return s.Sandbox.Enabled != nil && *s.Sandbox.Enabled, s.Sandbox.AllowUnsandboxedCommands == nil || *s.Sandbox.AllowUnsandboxedCommands, true
	}
	for _, p := range managed {
		if on, hatch, ok := read(p); ok && on {
			if hatch {
				return "none", p + " turns the sandbox on but leaves allowUnsandboxedCommands on, so a failed command may be retried outside it; set it to false"
			}
			if err := config.CheckSystemFile(p); err != nil {
				return "none", fmt.Sprintf("%s sets the sandbox, but %v", p, err)
			}
			return "managed", "Claude Code sandbox on in " + p + ", root-owned, with no unsandboxed retry (settings keys not tested live)"
		}
	}
	home, _ := os.UserHomeDir()
	for _, p := range []string{filepath.Join(home, ".claude", "settings.json"), ".claude/settings.json"} {
		if on, _, ok := read(p); ok && on {
			return "user", "the Claude Code sandbox is on in " + p + ", a file the agent's user can change: it counts only in managed settings"
		}
	}
	return "none", "no host sandbox found in Claude Code's managed settings; Codex sandbox modes are not checked"
}

func cmdDoctorBoundary(args []string, stdout, stderr io.Writer) int {
	wd, _ := os.Getwd()
	cfg, err := config.Load(config.UserPath(), wd)
	if err != nil {
		fmt.Fprintln(stderr, "applygate: config:", err)
		return 2
	}
	require := cfg.Boundary.Require
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--require" && i+1 < len(args):
			require = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--require="):
			require = strings.TrimPrefix(args[i], "--require=")
		default:
			fmt.Fprintf(stderr, "applygate: unknown option %q\n", args[i])
			return 2
		}
	}
	if require != "" && levelNum(require) < 0 {
		fmt.Fprintf(stderr, "applygate: assurance level %q is not one of L0, L1, L2, L3\n", require)
		return 2
	}
	fmt.Fprintln(stdout, "Boundary this machine has around applygate (it contacts AWS, Google Cloud, Azure and the clusters, read-only):")
	r := evalBoundary(cfg)
	for lvl := 1; lvl <= 3; lvl++ {
		for _, c := range r.checks {
			if c.level == lvl {
				fmt.Fprintf(stdout, "L%d %-12s %s\n", lvl, c.status, c.text)
			}
		}
	}
	for _, c := range r.checks {
		if c.level == 0 {
			fmt.Fprintf(stdout, "   %-12s %s\n", c.status, c.text)
		}
	}
	fmt.Fprintf(stdout, "\nAssurance level reached: L%d\n", r.reached)
	fmt.Fprintln(stdout, "L0 hook only, L1 managed and exclusive install, L2 audited credentials, L3 host sandbox plus attested CI apply and state guards. Above L0 the guarantee comes from the controls, not from the hook (docs/boundary.md).")
	if require != "" && r.reached < levelNum(require) {
		fmt.Fprintf(stdout, "\nRequired level %s not reached.\n", strings.ToUpper(require))
		return 1
	}
	return 0
}
