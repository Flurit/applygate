package preflight

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

// The plan gate runs terraform show, which starts the provider binaries in
// .terraform/providers to load their schemas. The agent can write that
// directory, so before show runs, every provider there must match a hash in
// .terraform.lock.hcl as git HEAD has it: a lock file the agent edited in
// the working tree is not trusted, and a provider binary it replaced does
// not match. Terraform itself and the user's CLI configuration are outside
// what this checks (docs/limits.md).

var (
	lockProvider = regexp.MustCompile(`(?m)^provider\s+"([^"]+)"\s*\{`)
	lockHash     = regexp.MustCompile(`"(h1:[A-Za-z0-9+/=]+)"`)
)

// VerifyProviders checks the providers under dataDir/providers against the
// lock file committed at git HEAD for dir. It returns nil when there are no
// providers to start.
func VerifyProviders(ctx context.Context, dir, dataDir string) error {
	root := filepath.Join(dataDir, "providers")
	dirs, err := providerDirs(root)
	if err != nil {
		return fmt.Errorf("cannot list %s: %v", root, err)
	}
	if len(dirs) == 0 {
		return nil
	}
	lock, err := headLockFile(ctx, dir)
	if err != nil {
		return err
	}
	hashes := parseLock(lock)
	for _, d := range dirs {
		rel, _ := filepath.Rel(root, d)
		parts := strings.Split(filepath.ToSlash(rel), "/") // host/namespace/type/version/os_arch
		addr := strings.Join(parts[:3], "/")
		want := hashes[addr]
		if len(want) == 0 {
			return fmt.Errorf("provider %s in %s is not in .terraform.lock.hcl at git HEAD", addr, root)
		}
		got, err := hash1(d)
		if err != nil {
			return fmt.Errorf("cannot hash provider %s: %v", d, err)
		}
		if !slices.Contains(want, got) {
			return fmt.Errorf("provider %s %s does not match .terraform.lock.hcl at git HEAD (%s); it may have been replaced", addr, parts[3], got)
		}
	}
	return nil
}

// providerDirs returns the unpacked package directories
// (host/namespace/type/version/os_arch) under root.
func providerDirs(root string) ([]string, error) {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return nil, nil
	}
	var out []string
	var walk func(d string, depth int) error
	walk = func(d string, depth int) error {
		if depth == 5 {
			out = append(out, d)
			return nil
		}
		ents, err := os.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range ents {
			p := filepath.Join(d, e.Name())
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				if err := walk(p, depth+1); err != nil {
					return err
				}
			} else if depth < 5 {
				return fmt.Errorf("unexpected file %s", p)
			}
		}
		return nil
	}
	return out, walk(root, 0)
}

func headLockFile(ctx context.Context, dir string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := gitCommand(ctx, dir, "cat-file", "-p", "HEAD:./.terraform.lock.hcl")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("no .terraform.lock.hcl committed at git HEAD for %s, so the providers show would start cannot be verified: %s", dir, firstLine(stderr.String()))
	}
	return out, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// parseLock returns the h1 hashes per provider address in a lock file. An
// address without a host gets registry.terraform.io.
func parseLock(b []byte) map[string][]string {
	out := map[string][]string{}
	s := string(b)
	locs := lockProvider.FindAllStringSubmatchIndex(s, -1)
	for i, l := range locs {
		end := len(s)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		addr := s[l[2]:l[3]]
		if strings.Count(addr, "/") == 1 {
			addr = "registry.terraform.io/" + addr
		}
		for _, m := range lockHash.FindAllStringSubmatch(s[l[1]:end], -1) {
			out[addr] = append(out[addr], m[1])
		}
	}
	return out
}

// hash1 is Terraform's h1 package hash (golang.org/x/mod's dirhash Hash1):
// the SHA-256 of the sorted "sha256  name" lines of every file.
func hash1(dir string) (string, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	var files []string
	err = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			rel, _ := filepath.Rel(root, p)
			files = append(files, filepath.ToSlash(rel))
		} else if !fi.IsDir() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	sum := sha256.New()
	for _, f := range files {
		fh, err := os.Open(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return "", err
		}
		h := sha256.New()
		_, err = io.Copy(h, fh)
		fh.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(sum, "%x  %s\n", h.Sum(nil), f)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(sum.Sum(nil)), nil
}

// UpstreamLock reports why the lock file committed at HEAD cannot vouch for
// the providers: it differs from the one on the branch's upstream. An agent
// can commit a lock file with a replaced provider's hash; it cannot change
// the upstream branch without a push others review. nil when the branch
// has no upstream, or the two agree.
func UpstreamLock(ctx context.Context, dir string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := gitCommand(ctx, dir, "cat-file", "-p", "@{upstream}:./.terraform.lock.hcl")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	up, err := cmd.Output()
	if err != nil {
		e := stderr.String()
		if strings.Contains(e, "does not exist in") || strings.Contains(e, "exists on disk, but not in") {
			return fmt.Errorf("the lock file committed at HEAD is not on the upstream branch, so its provider hashes cannot be trusted")
		}
		return nil // no upstream, or a detached HEAD
	}
	head, err := headLockFile(ctx, dir)
	if err != nil {
		return err
	}
	if !bytes.Equal(up, head) {
		return fmt.Errorf("the lock file committed at HEAD differs from the upstream branch's, so its provider hashes cannot be trusted")
	}
	return nil
}

// RunsPrograms reports configuration that makes Terraform run a program
// while it plans, in dir's configuration, the local modules it calls, the
// modules init downloaded into dataDir and every directory the module
// manifest names: a data source that runs one (external, local_command,
// shell_*), a provider or backend block with an exec block, or one that
// reads a kubeconfig or AWS config file other than the user's own (which
// are guard files), whose exec or credential_process entries run programs.
// "" when there is none. The files are read with the HCL and JSON parsers
// Terraform uses, .tofu files included; a file that cannot be read or
// parsed, or a configuration too large to read in full, counts as one that
// may.
func RunsPrograms(dir, dataDir string) string {
	seen := map[string]bool{}
	files := 0
	var scan func(d string, depth int) string
	scan = func(d string, depth int) string {
		d = filepath.Clean(d)
		if seen[d] {
			return ""
		}
		if depth > 10 {
			return "modules nested deeper than applygate reads"
		}
		seen[d] = true
		ents, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				return ""
			}
			return "a module directory that cannot be read: " + d
		}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !configName(n) {
				continue
			}
			if files++; files > 2000 {
				return "more configuration files than applygate reads"
			}
			f := filepath.Join(d, n)
			file, why := readConfig(f)
			if why != "" {
				return why
			}
			if why := runsIn(file.Body, f); why != "" {
				return why
			}
			for _, src := range moduleSources(file.Body) {
				if strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") {
					if why := scan(filepath.Join(d, src), depth+1); why != "" {
						return why
					}
				}
			}
		}
		return ""
	}
	if why := scan(dir, 0); why != "" {
		return why
	}
	// The module manifest says where each module's files are: Terraform
	// loads a module from whatever directory it names.
	if b, err := os.ReadFile(filepath.Join(dataDir, "modules", "modules.json")); err == nil {
		var m struct{ Modules []struct{ Dir string } }
		if json.Unmarshal(b, &m) != nil {
			return "a module manifest that cannot be read: " + filepath.Join(dataDir, "modules", "modules.json")
		}
		for _, mod := range m.Modules {
			d := mod.Dir
			if d == "" {
				continue
			}
			if !filepath.IsAbs(d) {
				d = filepath.Join(dir, d)
			}
			if why := scan(d, 1); why != "" {
				return why
			}
		}
	} else if !os.IsNotExist(err) {
		return "a module manifest that cannot be read: " + filepath.Join(dataDir, "modules", "modules.json")
	}
	var why string
	_ = filepath.WalkDir(filepath.Join(dataDir, "modules"), func(p string, e os.DirEntry, err error) error {
		if err != nil || !e.IsDir() {
			return nil
		}
		if why = scan(p, 0); why != "" {
			return filepath.SkipAll
		}
		return nil
	})
	return why
}

// configName reports a file name Terraform or OpenTofu reads as
// configuration.
func configName(n string) bool {
	if strings.HasPrefix(n, ".") || strings.HasPrefix(n, "#") || strings.HasSuffix(n, "~") {
		return false
	}
	for _, x := range []string{".tf", ".tf.json", ".tofu", ".tofu.json"} {
		if strings.HasSuffix(n, x) {
			return true
		}
	}
	return false
}

// MaxConfigFile is the largest configuration file the hook parses: the
// parser takes hundreds of times a file's size in memory.
const MaxConfigFile = 1 << 20

// readConfig parses one configuration file, or says why it cannot.
func readConfig(f string) (*hcl.File, string) {
	src, err := readCapped(f, MaxConfigFile)
	if err != nil {
		return nil, "a configuration file that cannot be read: " + f + " (" + err.Error() + ")"
	}
	var file *hcl.File
	var diags hcl.Diagnostics
	if strings.HasSuffix(f, ".json") {
		file, diags = hcljson.Parse(src, f)
	} else {
		file, diags = hclsyntax.ParseConfig(src, f, hcl.Pos{Line: 1, Column: 1})
	}
	if diags.HasErrors() || file == nil {
		return nil, "a configuration file that does not parse: " + f
	}
	return file, ""
}

// readCapped reads a regular file of at most max bytes.
func readCapped(f string, max int64) ([]byte, error) {
	fi, err := os.Stat(f)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	fh, err := os.Open(f)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b, nil
}

var (
	runsTopSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{
		{Type: "data", LabelNames: []string{"type", "name"}},
		{Type: "provider", LabelNames: []string{"name"}},
		{Type: "terraform"},
		{Type: "check", LabelNames: []string{"name"}},
		{Type: "resource", LabelNames: []string{"type", "name"}},
	}}
	runsCheckSchema     = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "data", LabelNames: []string{"type", "name"}}}}
	runsTerraformSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "backend", LabelNames: []string{"type"}}}}
	// programFiles are the provider and backend attributes that name a
	// kubeconfig or AWS config file, whose exec and credential_process
	// entries run programs.
	programFiles     = []string{"config_path", "config_paths", "shared_config_files", "shared_credentials_files", "shared_credentials_file", "shared_config_file", "kubeconfig", "kubeconfig_path", "kubeconfig_file", "kube_config_path"}
	runsNestedSchema = &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: "config_path"}, {Name: "config_paths"}, {Name: "shared_config_files"}, {Name: "shared_credentials_files"}, {Name: "shared_credentials_file"}, {Name: "shared_config_file"}, {Name: "kubeconfig"}, {Name: "kubeconfig_path"}, {Name: "kubeconfig_file"}, {Name: "kube_config_path"}, {Name: "exec"}, {Name: "ssh_opts"}, {Name: "kubernetes"}},
		Blocks:     []hcl.BlockHeaderSchema{{Type: "exec"}, {Type: "kubernetes"}, {Type: "dynamic", LabelNames: []string{"name"}}},
	}
	moduleSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "module", LabelNames: []string{"name"}}}}
)

// RunsBackendPrograms reports a backend block in dir's configuration that
// makes Terraform run a program when it configures the backend (init,
// output, state, workspace): an exec block, or a config file naming a
// credential_process or exec entry. "" when there is none.
func RunsBackendPrograms(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !configName(n) {
			continue
		}
		f := filepath.Join(dir, n)
		file, why := readConfig(f)
		if why != "" {
			return why
		}
		top, _, _ := file.Body.PartialContent(runsTopSchema)
		for _, b := range top.Blocks {
			if b.Type != "terraform" {
				continue
			}
			inner, _, _ := b.Body.PartialContent(runsTerraformSchema)
			for _, be := range inner.Blocks {
				if why := runsNested(be.Body, "backend \""+be.Labels[0]+"\"", f, 0); why != "" {
					return why
				}
			}
		}
	}
	return ""
}

// runsIn reports what in one file's body makes Terraform run a program.
func runsIn(body hcl.Body, f string) string {
	top, _, _ := body.PartialContent(runsTopSchema)
	for _, b := range top.Blocks {
		switch b.Type {
		case "check":
			// A data source scoped to a check block is read at plan time.
			inner, _, _ := b.Body.PartialContent(runsCheckSchema)
			for _, d := range inner.Blocks {
				if t := d.Labels[0]; t == "external" || t == "local_command" || strings.HasPrefix(t, "shell_") {
					return "data \"" + t + "\" in a check block in " + f + " runs a program during plan"
				}
			}
		case "resource":
			if t := b.Labels[0]; t == "shell_script" || strings.HasPrefix(t, "shell_") || t == "null_resource" && false || t == "external" {
				return "resource \"" + t + "\" in " + f + " runs a program"
			}
		case "data":
			if t := b.Labels[0]; t == "external" || t == "local_command" || strings.HasPrefix(t, "shell_") {
				return "data \"" + t + "\" in " + f + " runs a program during plan"
			}
		case "provider":
			if why := runsNested(b.Body, "provider \""+b.Labels[0]+"\"", f, 0); why != "" {
				return why
			}
		case "terraform":
			inner, _, _ := b.Body.PartialContent(runsTerraformSchema)
			for _, be := range inner.Blocks {
				if why := runsNested(be.Body, "backend \""+be.Labels[0]+"\"", f, 0); why != "" {
					return why
				}
			}
		}
	}
	return ""
}

func runsNested(body hcl.Body, what, f string, depth int) string {
	c, _, _ := body.PartialContent(runsNestedSchema)
	for _, n := range programFiles {
		if a, ok := c.Attributes[n]; ok && !userConfigFile(a.Expr) {
			return what + " in " + f + " sets " + n + ", whose file can run a program (exec, credential_process)"
		}
	}
	// exec as an attribute (exec = { command = ... }) and ssh_opts
	// (ProxyCommand) run programs the same way a block does.
	for _, n := range []string{"exec", "ssh_opts", "credential_process", "credentials_process"} {
		if _, ok := c.Attributes[n]; ok {
			return what + " in " + f + " sets " + n + ", which runs a program"
		}
	}
	// The helm provider takes kubernetes = { ... } as an attribute object:
	// its exec and config_path are the same.
	if a, ok := c.Attributes["kubernetes"]; ok {
		v, d := a.Expr.Value(emptyCtx)
		safe := false
		if !d.HasErrors() && v.IsWhollyKnown() && !v.IsNull() && (v.Type().IsObjectType() || v.Type().IsMapType()) {
			safe = true
			for it := v.ElementIterator(); it.Next(); {
				k, _ := it.Element()
				if kn := k.AsString(); kn == "exec" || strings.HasPrefix(kn, "config_path") || strings.Contains(kn, "kubeconfig") {
					safe = false
				}
			}
		}
		if !safe {
			return what + " in " + f + " sets kubernetes as an attribute object that may hold exec or config_path, which run programs"
		}
	}
	for _, nb := range c.Blocks {
		if nb.Type == "exec" || nb.Type == "dynamic" && len(nb.Labels) > 0 && (nb.Labels[0] == "exec" || nb.Labels[0] == "kubernetes") {
			return what + " in " + f + " has an exec block (or one generated by dynamic), which runs a program"
		}
		if depth < 3 {
			if why := runsNested(nb.Body, what, f, depth+1); why != "" {
				return why
			}
		}
	}
	return ""
}

// userConfigFile reports an attribute that names only the user's own
// kubeconfig or AWS config (guard files the agent cannot write).
func userConfigFile(e hcl.Expression) bool {
	v, d := e.Value(emptyCtx)
	if d.HasErrors() || !v.IsWhollyKnown() || v.IsNull() {
		return false
	}
	var paths []string
	switch {
	case v.Type() == cty.String:
		paths = []string{v.AsString()}
	case v.Type().IsListType() || v.Type().IsTupleType() || v.Type().IsSetType():
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			if ev.Type() != cty.String || ev.IsNull() {
				return false
			}
			paths = append(paths, ev.AsString())
		}
	default:
		return false
	}
	for _, p := range paths {
		switch p {
		case "~/.kube/config", "~/.aws/config", "~/.aws/credentials", "$HOME/.kube/config", "$HOME/.aws/config":
		default:
			return false
		}
	}
	return len(paths) > 0
}

// moduleSources returns the literal source of each module block.
func moduleSources(body hcl.Body) []string {
	c, _, _ := body.PartialContent(moduleSchema)
	var out []string
	for _, mb := range c.Blocks {
		attrs, _ := mb.Body.JustAttributes()
		if a, ok := attrs["source"]; ok {
			if v, ok := literal(a.Expr); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

// InitSafe reports whether a plain terraform init in dir installs only what
// the committed lock file vouches for: the lock file and the module sources
// are as committed (no drift since HEAD), and the lock lists every provider
// the configuration requires, so init adds nothing and verifies every
// download against hashes the agent did not choose.
func InitSafe(ctx context.Context, dir string) bool {
	if LockfileDrift(dir) != nil {
		return false
	}
	lock, err := readCapped(filepath.Join(dir, ".terraform.lock.hcl"), MaxConfigFile)
	if err != nil {
		return false
	}
	have := map[string]bool{}
	for _, m := range lockProvider.FindAllSubmatch(lock, -1) {
		have[strings.ToLower(string(m[1]))] = true
	}
	// A provider the configuration uses without requiring it is the
	// hashicorp one of that name (aws for aws_db_instance).
	declared := map[string]bool{}
	for _, f := range parsedFiles(dir) {
		top, _, _ := f.Body.PartialContent(terraformSchema)
		for _, tb := range top.Blocks {
			rp, _, _ := tb.Body.PartialContent(requiredSchema)
			for _, b := range rp.Blocks {
				attrs, _ := b.Body.JustAttributes()
				for name := range attrs {
					declared[name] = true
				}
			}
		}
	}
	for _, f := range parsedFiles(dir) {
		impl, _, _ := f.Body.PartialContent(runsTopSchema)
		for _, b := range impl.Blocks {
			name := ""
			switch b.Type {
			case "resource", "data":
				name, _, _ = strings.Cut(b.Labels[0], "_")
			case "provider":
				name = b.Labels[0]
			}
			if name == "" || name == "terraform" || declared[name] {
				continue
			}
			if !have["registry.terraform.io/hashicorp/"+strings.ToLower(name)] {
				return false
			}
		}
	}
	for _, f := range parsedFiles(dir) {
		top, _, _ := f.Body.PartialContent(terraformSchema)
		for _, tb := range top.Blocks {
			if tb.Type != "terraform" {
				continue
			}
			rp, _, _ := tb.Body.PartialContent(requiredSchema)
			for _, b := range rp.Blocks {
				attrs, _ := b.Body.JustAttributes()
				for name, a := range attrs {
					src := ""
					if v, d := a.Expr.Value(emptyCtx); !d.HasErrors() && v.IsWhollyKnown() && !v.IsNull() {
						switch {
						case v.Type() == cty.String:
							src = v.AsString()
						case v.Type().IsObjectType() && v.Type().HasAttribute("source"):
							if sv := v.GetAttr("source"); sv.Type() == cty.String && !sv.IsNull() {
								src = sv.AsString()
							}
						}
					}
					if src == "" {
						src = "hashicorp/" + name
					}
					switch strings.Count(src, "/") {
					case 1:
						src = "registry.terraform.io/" + src
					case 0:
						return false
					}
					if !have[strings.ToLower(src)] {
						return false
					}
				}
			}
		}
	}
	return true
}
