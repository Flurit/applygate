// Package preflight inspects the local working directory of a Terraform or
// OpenTofu command: selected workspace, backend, stale state files, lock
// file drift, and the workspace a saved plan was made in. It reads local
// files only; the single optional network call (STS identity) is opt-in.
package preflight

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Severity of a finding.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Info     Severity = "info"
)

// Finding is one preflight or plan-gate result.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

// Backend is the backend configuration as recorded or declared.
type Backend struct {
	Type      string            `json:"type"`
	Config    map[string]string `json:"config,omitempty"`
	Declared  bool              `json:"-"`
	sourceTag string
}

// URL renders the backend for matching, e.g. "s3://bucket/key".
func (b *Backend) URL() string {
	if b == nil || b.Type == "" {
		return ""
	}
	switch b.Type {
	case "s3":
		return "s3://" + b.Config["bucket"] + "/" + b.Config["key"]
	case "gcs":
		return "gcs://" + b.Config["bucket"] + "/" + b.Config["prefix"]
	case "azurerm":
		return "azurerm://" + b.Config["storage_account_name"] + "/" + b.Config["container_name"] + "/" + b.Config["key"]
	case "remote", "cloud":
		return b.Type + "://" + b.Config["organization"] + "/" + b.Config["workspaces"]
	}
	return b.Type
}

// Remote reports whether state lives outside the working tree.
func (b *Backend) Remote() bool { return b != nil && b.Type != "" && b.Type != "local" }

// Workspace returns the selected workspace for dir: TF_WORKSPACE wins, then
// .terraform/environment, then "default".
func Workspace(dir string, env map[string]string) string {
	if w := env["TF_WORKSPACE"]; w != "" {
		return w
	}
	if dir != "" {
		dataDir := ".terraform"
		if d := env["TF_DATA_DIR"]; d != "" {
			dataDir = d
		}
		if b, err := os.ReadFile(filepath.Join(dir, dataDir, "environment")); err == nil {
			if w := strings.TrimSpace(string(b)); w != "" {
				return w
			}
		}
	}
	return "default"
}

// InitBackend reads the backend recorded by the last init in
// .terraform/terraform.tfstate.
func InitBackend(dir string) *Backend {
	b, err := os.ReadFile(filepath.Join(dir, ".terraform", "terraform.tfstate"))
	if err != nil {
		return nil
	}
	var raw struct {
		Backend *struct {
			Type   string         `json:"type"`
			Config map[string]any `json:"config"`
		} `json:"backend"`
	}
	if json.Unmarshal(b, &raw) != nil || raw.Backend == nil {
		return nil
	}
	be := &Backend{Type: raw.Backend.Type, Config: map[string]string{}}
	for k, v := range raw.Backend.Config {
		if s, ok := v.(string); ok {
			be.Config[k] = s
		}
	}
	return be
}

var (
	backendBlock = regexp.MustCompile(`(?s)\bbackend\s+"([A-Za-z0-9_-]+)"\s*\{`)
	cloudBlock   = regexp.MustCompile(`(?s)\bcloud\s*\{`)
	attrLine     = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"`)
)

// DeclaredBackend parses the backend block from *.tf files in dir. Only
// literal string attributes are read; this is not a full HCL parser.
func DeclaredBackend(dir string) *Backend {
	files, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	sort.Strings(files)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := stripComments(string(src))
		if loc := backendBlock.FindStringSubmatchIndex(s); loc != nil {
			body := braceBody(s, loc[1]-1)
			be := &Backend{Type: s[loc[2]:loc[3]], Config: map[string]string{}, Declared: true}
			for _, m := range attrLine.FindAllStringSubmatch(body, -1) {
				be.Config[m[1]] = m[2]
			}
			return be
		}
		if cloudBlock.MatchString(s) {
			return &Backend{Type: "cloud", Config: map[string]string{}, Declared: true}
		}
	}
	return nil
}

func stripComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func braceBody(s string, open int) string {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[open+1 : i]
			}
		}
	}
	return s[open+1:]
}

// BackendChanged compares the declared backend with the one recorded at
// init. It returns a finding when a literal attribute differs.
func BackendChanged(declared, recorded *Backend) *Finding {
	if declared == nil || recorded == nil {
		return nil
	}
	if declared.Type != recorded.Type {
		return &Finding{Rule: "backend-changed", Severity: High,
			Message:  "the backend block changed since terraform init (type " + recorded.Type + " -> " + declared.Type + ")",
			Evidence: []string{"recorded: " + recorded.URL(), "declared: " + declared.URL()}}
	}
	var diffs []string
	for _, k := range []string{"bucket", "key", "region", "dynamodb_table", "workspace_key_prefix", "profile", "role_arn", "path", "prefix", "organization"} {
		d, dok := declared.Config[k]
		r, rok := recorded.Config[k]
		if dok && rok && d != r {
			diffs = append(diffs, k+": "+r+" -> "+d)
		}
	}
	if len(diffs) == 0 {
		return nil
	}
	return &Finding{Rule: "backend-changed", Severity: High,
		Message: "the backend block changed since terraform init; state may be read from or written to a different place", Evidence: diffs}
}

var archiveExt = []string{".zip", ".tar", ".tar.gz", ".tgz"}

// StaleState looks for state files and archives containing state in dir
// (not in .terraform) when the backend keeps state elsewhere.
func StaleState(dir string, backend *Backend) *Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var states, archives []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(n, ".tfstate") || strings.HasSuffix(n, ".tfstate.backup") {
			states = append(states, n)
			continue
		}
		for _, ext := range archiveExt {
			if strings.HasSuffix(n, ext) {
				if inner := archiveStates(filepath.Join(dir, n)); len(inner) > 0 {
					archives = append(archives, n+" contains "+strings.Join(inner, ", "))
				}
				break
			}
		}
	}
	if backend.Remote() && len(states) > 0 {
		return &Finding{Rule: "stale-state", Severity: High,
			Message:  "local state files sit in a directory whose state lives in the " + backend.Type + " backend; they may be stale or from another environment",
			Evidence: states}
	}
	if len(archives) > 0 {
		return &Finding{Rule: "stale-state", Severity: High,
			Message:  "an archive in the working directory contains Terraform state; if it is unpacked, an old state could be used",
			Evidence: archives}
	}
	return nil
}

func archiveStates(path string) []string {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > 256<<20 {
		return nil
	}
	var names []string
	add := func(n string) {
		if strings.HasSuffix(n, ".tfstate") || strings.HasSuffix(n, ".tfstate.backup") {
			names = append(names, n)
		}
	}
	if strings.HasSuffix(path, ".zip") {
		zr, err := zip.OpenReader(path)
		if err != nil {
			return nil
		}
		defer zr.Close()
		for _, f := range zr.File {
			add(f.Name)
		}
		return names
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, "gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	for i := 0; i < 10000; i++ {
		h, err := tr.Next()
		if err != nil {
			break
		}
		add(h.Name)
	}
	return names
}

// LockfileDrift asks git whether .terraform.lock.hcl or module/provider
// sources changed since HEAD. It runs git read-only with a short timeout and
// returns nil when git or the repository is unavailable.
func LockfileDrift(dir string) *Finding {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "--no-optional-locks", "diff", "HEAD", "--no-color", "--no-ext-diff", "-U0", "--", ".terraform.lock.hcl", "*.tf")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var out bytes.Buffer
	cmd.Stdout = &out
	if cmd.Run() != nil {
		return nil
	}
	var ev []string
	file := ""
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "+++ b/") {
			file = strings.TrimPrefix(l, "+++ b/")
			continue
		}
		if !strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "-") || strings.HasPrefix(l, "+++") || strings.HasPrefix(l, "---") {
			continue
		}
		body := strings.TrimSpace(l[1:])
		if strings.HasSuffix(file, ".terraform.lock.hcl") || strings.HasPrefix(body, "source") || strings.HasPrefix(body, "version") && strings.HasSuffix(file, ".tf") {
			ev = append(ev, file+": "+l)
		}
		if len(ev) >= 8 {
			break
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return &Finding{Rule: "lockfile-drift", Severity: High,
		Message: "the provider lock file or module/provider sources changed since the last commit; review them before applying", Evidence: ev}
}

// PlanWorkspace reads the workspace recorded in a saved plan file. The plan
// is a zip whose "tfplan" entry is a protobuf message; field 13 is the
// backend and its field 3 the workspace name (Terraform 1.x and OpenTofu).
func PlanWorkspace(planPath string) (string, bool) {
	zr, err := zip.OpenReader(planPath)
	if err != nil {
		return "", false
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "tfplan" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", false
		}
		data, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		rc.Close()
		if err != nil {
			return "", false
		}
		backend, ok := pbField(data, 13)
		if !ok {
			return "", false
		}
		ws, ok := pbField(backend, 3)
		return string(ws), ok
	}
	return "", false
}

// pbField returns the first length-delimited field with the given number.
func pbField(b []byte, num uint64) ([]byte, bool) {
	for len(b) > 0 {
		key, n := uvarint(b)
		if n <= 0 {
			return nil, false
		}
		b = b[n:]
		field, wt := key>>3, key&7
		switch wt {
		case 0:
			_, n = uvarint(b)
			if n <= 0 {
				return nil, false
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, false
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return nil, false
			}
			b = b[4:]
		case 2:
			l, n := uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, false
			}
			v := b[n : n+int(l)]
			if field == num {
				return v, true
			}
			b = b[n+int(l):]
		default:
			return nil, false
		}
	}
	return nil, false
}

func uvarint(b []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, c := range b {
		if i == 10 {
			return 0, -1
		}
		if c < 0x80 {
			return x | uint64(c)<<s, i + 1
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return 0, 0
}

// CallerAccount runs "aws sts get-caller-identity" for a profile. It is only
// called when preflight.live_identity is enabled.
func CallerAccount(profile string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := []string{"sts", "get-caller-identity", "--output", "json"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	out, err := exec.CommandContext(ctx, "aws", args...).Output()
	if err != nil {
		return "", err
	}
	var id struct{ Account string }
	if err := json.Unmarshal(out, &id); err != nil {
		return "", err
	}
	return id.Account, nil
}

// StateInfo is the identity of a state file: its lineage and serial.
type StateInfo struct {
	Lineage string
	Serial  uint64
}

// ParseState reads lineage and serial from a state file's JSON.
func ParseState(b []byte) (StateInfo, bool) {
	var raw struct {
		Lineage string `json:"lineage"`
		Serial  uint64 `json:"serial"`
	}
	if json.Unmarshal(b, &raw) != nil || raw.Lineage == "" {
		return StateInfo{}, false
	}
	return StateInfo{Lineage: raw.Lineage, Serial: raw.Serial}, true
}

// PullState runs "<engine> state pull" in dir and returns the remote state.
// It is read-only but contacts the backend, so it is only called when
// preflight.live_state is enabled in the user config.
func PullState(parent context.Context, engine, dir string, timeout time.Duration) ([]byte, error) {
	bin := engine
	if bin == "" || bin == "terragrunt" {
		bin = "terraform"
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "state", "pull")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0", "CHECKPOINT_DISABLE=1")
	cmd.WaitDelay = 2 * time.Second
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s state pull cancelled or timed out after %s", bin, timeout)
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		return nil, fmt.Errorf("%s state pull failed: %v: %s", bin, err, msg)
	}
	return out, nil
}

// LineageMismatch compares local state files (names relative to dir) with
// the remote state and reports the ones that are foreign (another lineage),
// stale (behind the remote serial) or diverged (ahead of it). A local file
// identical in lineage and serial to the remote state produces no finding.
func LineageMismatch(dir string, states []string, remote []byte) *Finding {
	rs, ok := ParseState(remote)
	if !ok {
		return &Finding{Rule: "state-lineage", Severity: Info, Message: "the remote state could not be parsed for lineage and serial"}
	}
	var ev []string
	for _, n := range states {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		ls, ok := ParseState(b)
		switch {
		case !ok:
			continue
		case ls.Lineage != rs.Lineage:
			ev = append(ev, fmt.Sprintf("%s is from another state lineage (%s, remote is %s): foreign state", n, short(ls.Lineage), short(rs.Lineage)))
		case ls.Serial < rs.Serial:
			ev = append(ev, fmt.Sprintf("%s is behind the remote state (serial %d, remote %d): stale", n, ls.Serial, rs.Serial))
		case ls.Serial > rs.Serial:
			ev = append(ev, fmt.Sprintf("%s is ahead of the remote state (serial %d, remote %d): diverged", n, ls.Serial, rs.Serial))
		}
	}
	if len(ev) == 0 {
		return nil
	}
	return &Finding{Rule: "state-lineage", Severity: High,
		Message:  "local state files do not match the remote state's lineage and serial; a plan or destroy here may use the wrong state",
		Evidence: ev}
}

func short(lineage string) string {
	if len(lineage) > 8 {
		return lineage[:8] + "…"
	}
	return lineage
}
