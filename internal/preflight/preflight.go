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
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	Type     string            `json:"type"`
	Config   map[string]string `json:"config,omitempty"`
	Declared bool              `json:"-"`
	// Unreadable says why the declared backend could not be read in full
	// (a value built from variables or templates, a file that does not
	// parse): the state it points at is unknown.
	Unreadable string `json:"-"`
	sourceTag  string
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
	case "http":
		if a := b.Config["address"]; a != "" {
			return a
		}
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
		if b, err := os.ReadFile(filepath.Join(DataDir(dir, env), "environment")); err == nil {
			if w := strings.TrimSpace(string(b)); w != "" {
				return w
			}
		}
	}
	return "default"
}

// InitBackend reads the backend recorded by the last init in
// .terraform/terraform.tfstate.
func InitBackend(dir string) *Backend { return InitBackendEnv(dir, nil) }

// DataDir is the directory Terraform keeps its working data in: TF_DATA_DIR
// (relative to dir) when set, else .terraform.
func DataDir(dir string, env map[string]string) string {
	if d := env["TF_DATA_DIR"]; d != "" {
		if filepath.IsAbs(d) {
			return d
		}
		return filepath.Join(dir, d)
	}
	return filepath.Join(dir, ".terraform")
}

// InitBackendEnv reads the backend recorded by the last init in the data
// directory TF_DATA_DIR names, else .terraform.
func InitBackendEnv(dir string, env map[string]string) *Backend {
	b, err := os.ReadFile(filepath.Join(DataDir(dir, env), "terraform.tfstate"))
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

// DeclaredBackend reads the backend or cloud block from dir's configuration
// files as Terraform and OpenTofu do, with HashiCorp's HCL parser: .tf and
// .tf.json files (and OpenTofu's .tofu and .tofu.json, which replace the
// .tf file of the same name for tofu), skipping names that start with "."
// as both do, override files last. A value that is not a plain literal, a
// file that names a backend and does not parse, and Terraform and OpenTofu
// reading different backends are each returned with Unreadable set.
func DeclaredBackend(dir string) *Backend {
	tf, tofu := configFiles(dir)
	a := backendFrom(tf)
	if len(tofu) == 0 {
		return a
	}
	b := backendFrom(tofu)
	if !sameBackend(a, b) {
		if b == nil {
			b = &Backend{Type: "unknown", Config: map[string]string{}, Declared: true}
		}
		c := *b
		c.Unreadable = "Terraform and OpenTofu read different backends in " + dir
		return &c
	}
	return b
}

// configFiles lists the configuration files Terraform reads in dir, and,
// when dir has .tofu files, the ones OpenTofu reads.
func configFiles(dir string) (tf, tofu []string) {
	entries, _ := os.ReadDir(dir)
	byStem := map[string]string{} // stem -> .tofu file, for OpenTofu
	var tfFiles []string
	hasTofu := false
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "#") || strings.HasSuffix(n, "~") {
			continue
		}
		switch {
		case strings.HasSuffix(n, ".tf"), strings.HasSuffix(n, ".tf.json"):
			tfFiles = append(tfFiles, filepath.Join(dir, n))
		case strings.HasSuffix(n, ".tofu"), strings.HasSuffix(n, ".tofu.json"):
			hasTofu = true
			stem := strings.TrimSuffix(strings.TrimSuffix(n, ".json"), ".tofu")
			byStem[stem+filepath.Ext(strings.TrimSuffix(n, ".tofu"))] = filepath.Join(dir, n)
		}
	}
	tf = orderOverrides(tfFiles)
	if !hasTofu {
		return tf, nil
	}
	var tofuFiles []string
	for _, f := range tfFiles {
		n := filepath.Base(f)
		stem := strings.TrimSuffix(strings.TrimSuffix(n, ".json"), ".tf")
		if _, replaced := byStem[stem+filepath.Ext(strings.TrimSuffix(n, ".tf"))]; !replaced {
			tofuFiles = append(tofuFiles, f)
		}
	}
	for _, f := range byStem {
		tofuFiles = append(tofuFiles, f)
	}
	return tf, orderOverrides(tofuFiles)
}

// orderOverrides sorts files by name with override files last.
func orderOverrides(files []string) []string {
	var base, over []string
	for _, f := range files {
		n := filepath.Base(f)
		for _, ext := range []string{".json", ".tofu", ".tf"} {
			n = strings.TrimSuffix(n, ext)
		}
		if n == "override" || strings.HasSuffix(n, "_override") {
			over = append(over, f)
		} else {
			base = append(base, f)
		}
	}
	sort.Strings(base)
	sort.Strings(over)
	return append(base, over...)
}

func sameBackend(a, b *Backend) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Type == b.Type && a.Unreadable == b.Unreadable && reflect.DeepEqual(a.Config, b.Config)
}

// emptyCtx evaluates expressions with no variables or functions: a
// reference fails, and JSON strings are read as templates, as Terraform
// reads them.
var emptyCtx = &hcl.EvalContext{}

var (
	terraformSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "terraform"}}}
	backendSchema   = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "backend", LabelNames: []string{"type"}}, {Type: "cloud"}}}
	providerSchema  = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "provider", LabelNames: []string{"name"}}}}
	nestedSchema    = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "workspaces"}, {Type: "assume_role"}, {Type: "assume_role_with_web_identity"}, {Type: "endpoints"}}}
)

// backendFrom reads the backend the files declare; a later file's block
// replaces an earlier one's, as override files do.
func backendFrom(files []string) *Backend {
	var found *Backend
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var file *hcl.File
		var diags hcl.Diagnostics
		if strings.HasSuffix(f, ".json") {
			file, diags = hcljson.Parse(src, f)
		} else {
			file, diags = hclsyntax.ParseConfig(src, f, hcl.Pos{Line: 1, Column: 1})
		}
		if diags.HasErrors() || file == nil {
			if bytes.Contains(src, []byte("backend")) || bytes.Contains(src, []byte("cloud")) {
				found = &Backend{Type: "unknown", Config: map[string]string{}, Declared: true, Unreadable: filepath.Base(f) + " does not parse: " + diags.Error()}
			}
			continue
		}
		top, _, _ := file.Body.PartialContent(terraformSchema)
		for _, tb := range top.Blocks {
			inner, _, _ := tb.Body.PartialContent(backendSchema)
			for _, b := range inner.Blocks {
				be := &Backend{Type: "cloud", Config: map[string]string{}, Declared: true}
				if b.Type == "backend" {
					be.Type = b.Labels[0]
				}
				readBody(be, b.Body)
				found = be
			}
		}
	}
	return found
}

// readBody reads a backend block's literal attributes, and the workspace
// name or prefix of a cloud or remote backend. A value that refers to
// anything or is computed is not known.
func readBody(be *Backend, body hcl.Body) {
	nested, rest, _ := body.PartialContent(nestedSchema)
	for _, nb := range nested.Blocks {
		if nb.Type != "workspaces" {
			// assume_role and the like: their values (role_arn) are
			// name hints like any other.
			attrs, _ := attributesOf(nb.Body)
			for k, a := range attrs {
				if v, ok := scalar(a.Expr); ok {
					if _, set := be.Config[k]; !set {
						be.Config[k] = v
					}
				} else {
					be.Unreadable = "the backend's " + nb.Type + "." + k + " is computed"
				}
			}
			continue
		}
		attrs, _ := nb.Body.JustAttributes()
		for _, k := range []string{"name", "prefix", "project"} {
			if a, ok := attrs[k]; ok {
				if v, ok := literal(a.Expr); ok {
					be.Config["workspaces"] = v
				} else {
					be.Unreadable = "the backend's workspaces." + k + " is computed"
				}
			}
		}
	}
	attrs, diags := attributesOf(rest)
	if diags.HasErrors() {
		be.Unreadable = "the backend block cannot be read: " + diags.Error()
		return
	}
	for k, a := range attrs {
		v, err := a.Expr.Value(emptyCtx)
		if err.HasErrors() || !v.IsWhollyKnown() {
			be.Unreadable = "the backend's " + k + " is computed"
		} else if t, ok := scalarText(v); ok {
			be.Config[k] = t
		}
	}
}

// scalar is a literal string, bool or number as text; false when the value
// is computed or is a list or object.
func scalar(e hcl.Expression) (string, bool) {
	v, diags := e.Value(emptyCtx)
	if diags.HasErrors() || !v.IsWhollyKnown() {
		return "", false
	}
	return scalarText(v)
}

func scalarText(v cty.Value) (string, bool) {
	switch {
	case v.IsNull():
		return "", false
	case v.Type() == cty.String:
		return v.AsString(), true
	case v.Type() == cty.Bool:
		return strconv.FormatBool(v.True()), true
	case v.Type() == cty.Number:
		return v.AsBigFloat().Text('f', -1), true
	}
	return "", false
}

// attributesOf returns a body's attributes. A native-syntax body is read
// directly: its JustAttributes rejects nested blocks even when a schema has
// set them aside.
func attributesOf(body hcl.Body) (hcl.Attributes, hcl.Diagnostics) {
	if sb, ok := body.(*hclsyntax.Body); ok {
		out := make(hcl.Attributes, len(sb.Attributes))
		for k, a := range sb.Attributes {
			out[k] = a.AsHCLAttribute()
		}
		return out, nil
	}
	return body.JustAttributes()
}

func literal(e hcl.Expression) (string, bool) {
	v, diags := e.Value(emptyCtx)
	if diags.HasErrors() || !v.IsWhollyKnown() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

func clip(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

var (
	providerAWS = regexp.MustCompile(`(?s)\bprovider\s+"?aws"?\s*\{`)
	roleARN     = regexp.MustCompile(`(?m)^\s*role_arn\s*=\s*"([^"]*)"`)
)

// Vars are the input variable values a command gives Terraform: -var
// NAME=value pairs, -var-file files (absolute) and the environment
// (TF_VAR_NAME). Unknown says why some cannot be read.
type Vars struct {
	Values  map[string]string
	Files   []string
	Env     map[string]string
	Unknown string
}

// ProviderAWS returns the profile and role_arn values of the aws provider
// blocks in dir's configuration files, aliases included: each is a target
// the configuration may change. A value that is var.NAME gives every value
// the variable may have (-var, -var-file, TF_VAR_NAME, terraform.tfvars,
// *.auto.tfvars, its default). Any other computed value, or a variable with
// no value found, is unknown, and unknown says why (4H10).
func ProviderAWS(dir string, vars Vars) (profiles, roles []string, unknown string) {
	files := parsedFiles(dir)
	var vv *varValues
	values := func(what string, e hcl.Expression) []string {
		if v, ok := literal(e); ok {
			return []string{v}
		}
		tr, d := hcl.AbsTraversalForExpr(e)
		if d.HasErrors() || len(tr) != 2 || tr.RootName() != "var" {
			unknown = "the aws provider's " + what + " is computed"
			return nil
		}
		at, ok := tr[1].(hcl.TraverseAttr)
		if !ok {
			unknown = "the aws provider's " + what + " is computed"
			return nil
		}
		if vv == nil {
			vv = readVarValues(dir, files, vars)
		}
		got := vv.of(at.Name)
		why := vars.Unknown
		if why == "" {
			why = vv.bad
		}
		if len(got) == 0 || why != "" {
			unknown = "the aws provider's " + what + " is var." + at.Name + ", whose value is not known"
			if why != "" {
				unknown += " (" + why + ")"
			}
		}
		return got
	}
	for _, file := range files {
		top, _, _ := file.Body.PartialContent(providerSchema)
		for _, pb := range top.Blocks {
			if pb.Labels[0] != "aws" {
				continue
			}
			inner, rest, _ := pb.Body.PartialContent(nestedSchema)
			attrs, _ := attributesOf(rest)
			if a, ok := attrs["profile"]; ok {
				profiles = append(profiles, values("profile", a.Expr)...)
			}
			if a, ok := attrs["assume_role"]; ok {
				if v, d := a.Expr.Value(emptyCtx); !d.HasErrors() && v.IsWhollyKnown() && (v.Type().IsObjectType() || v.Type().IsMapType()) {
					if v.Type().HasAttribute("role_arn") {
						if r := v.GetAttr("role_arn"); r.Type() == cty.String && !r.IsNull() {
							roles = append(roles, r.AsString())
						}
					}
				} else {
					unknown = "the aws provider's assume_role is computed"
				}
			}
			for _, nb := range inner.Blocks {
				if nb.Type != "assume_role" && nb.Type != "assume_role_with_web_identity" {
					continue
				}
				na, _ := attributesOf(nb.Body)
				if a, ok := na["role_arn"]; ok {
					roles = append(roles, values(nb.Type+".role_arn", a.Expr)...)
				}
			}
		}
	}
	return profiles, roles, unknown
}

// parsedFiles parses dir's configuration files, Terraform's and OpenTofu's,
// each once; files that do not parse are left out.
func parsedFiles(dir string) []*hcl.File {
	tf, tofu := configFiles(dir)
	seen := map[string]bool{}
	var out []*hcl.File
	for _, f := range append(tf, tofu...) {
		if seen[f] {
			continue
		}
		seen[f] = true
		if file := parseFile(f); file != nil {
			out = append(out, file)
		}
	}
	return out
}

func parseFile(f string) *hcl.File {
	src, err := os.ReadFile(f)
	if err != nil {
		return nil
	}
	var file *hcl.File
	var diags hcl.Diagnostics
	if strings.HasSuffix(f, ".json") {
		file, diags = hcljson.Parse(src, f)
	} else {
		file, diags = hclsyntax.ParseConfig(src, f, hcl.Pos{Line: 1, Column: 1})
	}
	if diags.HasErrors() {
		return nil
	}
	return file
}

// varValues are the values each input variable may have; bad says why a
// -var-file the command names cannot be read.
type varValues struct {
	m   map[string][]string
	bad string
}

func (v *varValues) of(name string) []string { return v.m[name] }

var variableSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "variable", LabelNames: []string{"name"}}}}

func readVarValues(dir string, files []*hcl.File, vars Vars) *varValues {
	vv := &varValues{m: map[string][]string{}}
	add := func(name, v string) {
		if !slices.Contains(vv.m[name], v) {
			vv.m[name] = append(vv.m[name], v)
		}
	}
	for _, file := range files {
		top, _, _ := file.Body.PartialContent(variableSchema)
		for _, b := range top.Blocks {
			attrs, _ := attributesOf(b.Body)
			if a, ok := attrs["default"]; ok {
				if v, ok := scalar(a.Expr); ok {
					add(b.Labels[0], v)
				}
			}
		}
	}
	tfvars := []string{filepath.Join(dir, "terraform.tfvars"), filepath.Join(dir, "terraform.tfvars.json")}
	for _, pat := range []string{"*.auto.tfvars", "*.auto.tfvars.json"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		tfvars = append(tfvars, m...)
	}
	for i, f := range append(tfvars, vars.Files...) {
		file := parseFile(f)
		if file == nil {
			if i >= len(tfvars) {
				vv.bad = "the -var-file " + f + " cannot be read"
			}
			continue
		}
		attrs, _ := attributesOf(file.Body)
		for k, a := range attrs {
			if v, ok := scalar(a.Expr); ok {
				add(k, v)
			}
		}
	}
	for k, v := range vars.Env {
		if name, ok := strings.CutPrefix(k, "TF_VAR_"); ok {
			add(name, v)
		}
	}
	for k, v := range vars.Values {
		add(k, v)
	}
	return vv
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
// gitCommand is how the hook runs git in a repository. The repository and
// its config are the agent's to write, so git runs by an absolute path,
// without the system and global config, and with the config keys that start
// programs (fsmonitor, hooks, pagers) overridden; callers use plumbing that
// runs no filters, diff drivers or textconv.
func gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	base := []string{"-C", dir, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
		"-c", "core.sshCommand=false", "-c", "core.askPass=", "--no-pager"}
	cmd := exec.CommandContext(ctx, gitPath(), append(base, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.TempDir(), "LANG=C", "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_OPTIONAL_LOCKS=0", "GIT_ATTR_NOSYSTEM=1"}
	return cmd
}

var gitBin struct {
	once sync.Once
	path string
}

// gitPath is git from the system directories first, so a git the agent
// put earlier on PATH is not the one the hook runs.
func gitPath() string {
	gitBin.once.Do(func() {
		// On macOS /usr/bin/git is a shim that looks the real one up with
		// xcrun, which can be slow; the real binaries come first.
		for _, p := range []string{"/Library/Developer/CommandLineTools/usr/bin/git", "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
			"/usr/bin/git", "/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git"} {
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				gitBin.path = p
				return
			}
		}
		gitBin.path, _ = exec.LookPath("git")
		if gitBin.path == "" {
			gitBin.path = "git"
		}
	})
	return gitBin.path
}

// LockfileDrift reports lock-file and provider/module source changes since
// the last commit in dir. It compares the committed blobs (git cat-file,
// which runs no filters) with the files on disk, rather than running git
// diff, which can start the repository's fsmonitor, textconv and filters.
func LockfileDrift(dir string) *Finding {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	files, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	files = append([]string{filepath.Join(dir, ".terraform.lock.hcl")}, files...)
	var ev []string
	for _, f := range files {
		now, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		name := filepath.Base(f)
		cmd := gitCommand(ctx, dir, "cat-file", "-p", "HEAD:./"+name)
		var out bytes.Buffer
		cmd.Stdout = &out
		if cmd.Run() != nil {
			continue // not committed, or not a repository
		}
		if bytes.Equal(out.Bytes(), now) {
			continue
		}
		old := map[string]bool{}
		for _, l := range strings.Split(out.String(), "\n") {
			old[l] = true
		}
		cur := map[string]bool{}
		for _, l := range strings.Split(string(now), "\n") {
			cur[l] = true
		}
		var changed []string
		for _, l := range strings.Split(string(now), "\n") {
			if !old[l] {
				changed = append(changed, "+"+l)
			}
		}
		for _, l := range strings.Split(out.String(), "\n") {
			if !cur[l] {
				changed = append(changed, "-"+l)
			}
		}
		for _, l := range changed {
			body := strings.TrimSpace(l[1:])
			if name == ".terraform.lock.hcl" && body != "" || strings.HasPrefix(body, "source") || strings.HasPrefix(body, "version") && strings.HasSuffix(name, ".tf") {
				ev = append(ev, name+": "+l)
			}
			if len(ev) >= 8 {
				break
			}
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

// PullState runs "<bin> state pull" in dir and returns the remote state.
// It is read-only but contacts the backend, so it is only called when
// preflight.live_state is enabled in the user config.
func PullState(parent context.Context, bin, dir string, timeout time.Duration) ([]byte, error) {
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

// BackendFromConfig returns the backend a "terraform init -backend-config ..."
// in dir would configure: the declared backend block (or, without one, the
// recorded backend's type) with each -backend-config file or key=value pair
// applied in order. A file that cannot be read returns an error and a nil
// backend, because the target is then unknown.
func BackendFromConfig(dir string, declared, recorded *Backend, configs []string, readFile func(string) ([]byte, error)) (*Backend, error) {
	be := &Backend{Config: map[string]string{}}
	switch {
	case declared != nil:
		// A computed value in the block stays unknown: a file or pair
		// may not set it (4H9).
		be.Type, be.Unreadable = declared.Type, declared.Unreadable
		for k, v := range declared.Config {
			be.Config[k] = v
		}
	case recorded != nil:
		be.Type = recorded.Type
	}
	for _, c := range configs {
		if k, v, ok := strings.Cut(c, "="); ok && !strings.ContainsAny(k, "/\\.") {
			be.Config[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
			continue
		}
		p := c
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		b, err := readFile(p)
		if err != nil {
			return nil, err
		}
		if err := applyConfigFile(be, p, b); err != nil {
			return nil, err
		}
	}
	return be, nil
}

// applyConfigFile reads a -backend-config file as Terraform does, as HCL or
// (with a .json name) JSON, and sets its values on be. A file that does not
// parse, or a value that is not a literal, is an error: the target is then
// unknown.
func applyConfigFile(be *Backend, path string, src []byte) error {
	var file *hcl.File
	var diags hcl.Diagnostics
	if strings.HasSuffix(path, ".json") {
		file, diags = hcljson.Parse(src, path)
	} else {
		file, diags = hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	}
	if diags.HasErrors() || file == nil {
		return fmt.Errorf("%s does not parse: %s", filepath.Base(path), diags.Error())
	}
	got := &Backend{Config: map[string]string{}}
	readBody(got, file.Body)
	if got.Unreadable != "" {
		return fmt.Errorf("%s: %s", filepath.Base(path), got.Unreadable)
	}
	for k, v := range got.Config {
		be.Config[k] = v
	}
	return nil
}
