package policy

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Flurit/applygate/internal/classify"
	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/preflight"
	"github.com/Flurit/applygate/internal/safefile"
	"github.com/Flurit/applygate/internal/shell"
)

// lineageCheck runs the opt-in state pull and compares the local state files
// named in the stale-state finding with the remote state.
func lineageCheck(a classify.Action, be *preflight.Backend, stale preflight.Finding, deps Deps) *preflight.Finding {
	var states []string
	for _, e := range stale.Evidence {
		if strings.HasSuffix(e, ".tfstate") || strings.HasSuffix(e, ".tfstate.backup") {
			states = append(states, e)
		}
	}
	if len(states) == 0 {
		return nil
	}
	remote, err := deps.StatePull(a.Engine, a.Dir)
	if err != nil {
		return &preflight.Finding{Rule: "state-lineage", Severity: preflight.Info, Message: "live state check failed: " + err.Error()}
	}
	return preflight.LineageMismatch(a.Dir, states, remote)
}

// terraformDir reports whether dir holds Terraform configuration or working
// data.
func terraformDir(dir string) bool {
	for _, pat := range []string{"*.tf", "*.tf.json", ".terraform", "terragrunt.hcl"} {
		if m, _ := filepath.Glob(filepath.Join(dir, pat)); len(m) > 0 {
			return true
		}
	}
	return false
}

// otherRepo reports whether dir is under a repository config the session's
// config did not read.
func otherRepo(cfg *config.Config, dir string) bool {
	if dir == cfg.LoadedFor {
		// Load looked up this directory's configs: none is unread.
		return false
	}
	read := map[string]bool{}
	for _, p := range append(append([]string(nil), cfg.Sources...), cfg.Untrusted...) {
		read[p] = true
	}
	for _, p := range config.RepoConfigs(dir) {
		if !read[p] {
			return true
		}
	}
	return false
}

// DirSignals are the tier signals of a Terraform directory as the hook reads
// them: the path, the selected workspace, and the recorded backend, else the
// declared one.
func DirSignals(dir string, env map[string]string) (config.Signals, *preflight.Backend) {
	sig := config.Signals{Dir: dir, Workspace: preflight.Workspace(dir, env)}
	sig.ProviderProfiles, sig.ProviderRoles, sig.ProviderUnknown = preflight.ProviderAWS(dir, preflight.Vars{Env: env})
	addProviderTargets(&sig, dir, env, nil)
	if why := preflight.ConfigUnreadable(dir); why != "" && sig.ProviderUnknown == "" {
		sig.ProviderUnknown = why
	}
	be := preflight.InitBackendEnv(dir, env)
	if be == nil {
		be = preflight.DeclaredBackend(dir)
	}
	if be != nil {
		if be.Unreadable != "" {
			sig.BackendUnknown = be.Unreadable
		}
		sig.Backend, sig.BackendValues = be.URL(), be.Config
		if p := be.Config["profile"]; p != "" && awsProfileEnv(env) == "" {
			sig.AWSProfile = p
		}
	}
	if p := awsProfileEnv(env); p != "" {
		sig.AWSProfile = p
	}
	// Where the state is: a local backend's path or workspace_dir, and local
	// state files that are links into another directory.
	if be != nil && be.Type == "local" {
		for _, k := range []string{"path", "workspace_dir"} {
			if be.Config[k] != "" {
				sig.StateDirs = append(sig.StateDirs, filepath.Dir(shell.PhysicalJoin(dir, be.Config[k])))
			}
		}
	}
	for _, n := range []string{"terraform.tfstate", "terraform.tfstate.d", "terraform.tfstate.backup"} {
		p := filepath.Join(dir, n)
		if r, err := filepath.EvalSymlinks(p); err == nil && filepath.Clean(r) != filepath.Clean(p) {
			sig.StateDirs = append(sig.StateDirs, filepath.Dir(r))
		}
	}
	for _, n := range []string{"terragrunt.hcl", "terragrunt.hcl.json"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			// A Terragrunt unit: its remote_state and local source are
			// signals too (terragrunt run --all, plan-check in a unit).
			terragruntSignals(&sig, classify.Action{Dir: dir, Engine: "terragrunt"}, be)
			break
		}
	}
	return sig, be
}

// terragruntSignals adds what the unit's terragrunt.hcl and --source say:
// remote_state values as name hints, and a local source's directory.
func terragruntSignals(sig *config.Signals, a classify.Action, be *preflight.Backend) {
	tg := preflight.ReadTerragrunt(a.Dir)
	source := a.Source
	if tg != nil {
		vals := map[string]string{}
		if be != nil {
			maps.Copy(vals, be.Config)
		}
		for k, v := range tg.Backend {
			if vals[k] == "" {
				vals[k] = v
			}
		}
		sig.BackendValues = vals
		if tg.Unknown != "" && sig.BackendUnknown == "" {
			sig.BackendUnknown = tg.Unknown
		}
		if source == "" {
			source = tg.Source
		}
	}
	if a.SourceUnknown {
		sig.BackendUnknown = "the terragrunt --source cannot be resolved statically"
	}
	// A local path: not a URL, a go-getter forced source (git::, s3::) or a
	// registry address (tfr:).
	if source != "" && !strings.Contains(source, "://") && !strings.Contains(source, "::") && !strings.HasPrefix(source, "tfr:") && !strings.HasPrefix(source, "git@") {
		p, _, _ := strings.Cut(source, "?")
		p = strings.Replace(p, "//", "/", 1)
		sig.SourceDirs = append(sig.SourceDirs, shell.PhysicalJoin(a.Dir, p))
	}
}

// awsProfileEnv is the profile the AWS CLI and SDKs pick from the
// environment: AWS_PROFILE, else AWS_DEFAULT_PROFILE.
func awsProfileEnv(env map[string]string) string {
	if p := env["AWS_PROFILE"]; p != "" {
		return p
	}
	return env["AWS_DEFAULT_PROFILE"]
}

// subtreeResolve is the tier of a command that runs in every Terragrunt unit
// under dir: the most protected of dir and each unit's own signals. When
// the units cannot all be listed (too many, unreadable), it is the most
// protected tier anything under dir could have.
func subtreeResolve(cfg *config.Config, dir string, sig config.Signals, env map[string]string) config.Resolution {
	best := cfg.Resolve(sig)
	n, complete := 0, true
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			complete = false
			return filepath.SkipDir
		}
		if d.IsDir() {
			if n++; n > 2000 {
				complete = false
				return filepath.SkipAll
			}
			if name := d.Name(); p != dir && (name == ".git" || name == ".terraform" || name == ".terragrunt-cache") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// A linked unit or directory could lead anywhere.
			complete = false
			return nil
		}
		if d.Name() != "terragrunt.hcl" && d.Name() != "terragrunt.hcl.json" {
			return nil
		}
		usig, _ := DirSignals(filepath.Dir(p), env)
		if r := cfg.Resolve(usig); r.Tier.Rank() > best.Tier.Rank() {
			best = config.Resolution{Tier: r.Tier, Env: r.Env, Matched: append([]string{"terragrunt runs the unit in " + filepath.Dir(p)}, r.Matched...)}
		}
		return nil
	})
	if !complete {
		return cfg.ResolveUnder(dir, sig, "terragrunt runs every unit under "+dir+", and they could not all be listed")
	}
	return best
}

// unknownSignal says why the target of a cloud or Terraform action cannot
// be told ("" when it can).
func unknownSignal(a classify.Action) string {
	if a.Engine == "" {
		return ""
	}
	if why := credFileRuns(a); why != "" {
		return why
	}
	if a.TargetUnknown != "" {
		return a.TargetUnknown
	}
	for _, k := range shell.TierEnv {
		if v, set := a.Env[k]; set && v == "" {
			return k + " is set to a value that cannot be resolved statically, so what it selects is unknown"
		}
	}
	for k, v := range a.Env {
		if strings.HasPrefix(k, "TF_CLI_ARGS_") && v == "" && a.Engine != "" {
			return k + " is set to a value that cannot be resolved statically"
		}
	}
	return ""
}

// absEnvPaths makes the relative config paths in env absolute against the
// command's directory, where the program resolves them.
func absEnvPaths(env map[string]string, dir string) {
	if dir == "" {
		return
	}
	for _, k := range []string{"KUBECONFIG", "CLOUDSDK_CONFIG", "AZURE_CONFIG_DIR", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		v := env[k]
		if v == "" {
			continue
		}
		parts := filepath.SplitList(v)
		for i, p := range parts {
			if p != "" && !filepath.IsAbs(p) && !strings.HasPrefix(p, "~") {
				parts[i] = shell.PhysicalJoin(dir, p)
			}
		}
		env[k] = strings.Join(parts, string(filepath.ListSeparator))
	}
}

// streamPath reports a planfile path that is not a regular file on disk: a
// device, a pipe or a descriptor, by any spelling (//dev/stdin, /./dev/fd/3)
// or through a link.
func streamPath(p string) bool {
	c := filepath.ToSlash(filepath.Clean(p))
	if r, err := filepath.EvalSymlinks(p); err == nil {
		c = filepath.ToSlash(r)
	}
	if strings.HasPrefix(c, "/dev/") || strings.HasPrefix(c, "/proc/") {
		return true
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.Mode().IsRegular()
}

// addProviderTargets adds what the google, kubernetes and azurerm provider
// blocks in dir name to sig.
func addProviderTargets(sig *config.Signals, dir string, env map[string]string, read func(string) ([]byte, error)) {
	t := preflight.ProviderTargets(dir)
	if read == nil {
		read = os.ReadFile
	}
	// What the providers read from the environment when the block names
	// nothing: the project, the subscription, the kube context.
	if sig.GCPProject == "" {
		for _, k := range []string{"GOOGLE_PROJECT", "GOOGLE_CLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT", "GCLOUD_PROJECT"} {
			if v := env[k]; v != "" {
				t.GCPProjects = append(t.GCPProjects, v)
			}
		}
	}
	for _, k := range []string{"ARM_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID"} {
		if v := env[k]; v != "" {
			t.AzureSubscriptions = append(t.AzureSubscriptions, v)
		}
	}
	if v := env["KUBE_CTX"]; v != "" {
		t.KubeContexts = append(t.KubeContexts, v)
	}
	// config_path names a kubeconfig, whose current context is the one the
	// provider uses when it names none; KUBE_CONFIG_PATH(S) does the same
	// from the environment.
	kc := append([]string(nil), t.KubeConfigs...)
	for _, k := range []string{"KUBE_CONFIG_PATH", "KUBE_CONFIG_PATHS"} {
		if v := env[k]; v != "" {
			kc = append(kc, filepath.SplitList(v)...)
			t.UsesKube = true
		}
	}
	for _, p := range kc {
		if !filepath.IsAbs(p) {
			p = shell.PhysicalJoin(dir, p)
		}
		if c := preflight.KubeContext(map[string]string{"KUBECONFIG": p}, read); c != "" {
			t.KubeContexts = append(t.KubeContexts, c)
		} else if t.Unknown == "" {
			t.Unknown = "the kubeconfig " + p + " names no current context applygate can read"
		}
	}
	if t.UsesKube && len(t.KubeContexts) == 0 && env["KUBE_CTX"] == "" {
		if c := preflight.KubeContext(env, read); c != "" {
			t.KubeContexts = append(t.KubeContexts, c)
		}
	}
	sig.ProviderProjects, sig.ProviderContexts, sig.ProviderSubscriptions = t.GCPProjects, t.KubeContexts, t.AzureSubscriptions
	if t.Unknown != "" && sig.ProviderUnknown == "" {
		sig.ProviderUnknown = t.Unknown
	}
}

var (
	credProcessRe = regexp.MustCompile(`(?mi)^\s*(credential_process|credentials_process)\s*=|^\s*exec\s*:|^\s*auth-provider\s*:|^\s*command\s*:`)
)

// credFileRuns reports a credentials or kube config file the command points
// the CLI at, other than the user's own (a guard file), that names a
// program to run: credential_process in an AWS config, exec or
// auth-provider in a kubeconfig. An unreadable file is not a finding: it
// runs nothing.
func credFileRuns(a classify.Action) string {
	for _, k := range classify.CredFileEnv() {
		v := a.Env[k]
		if tv := a.TargetEnv[k]; tv != "" {
			v = tv
		}
		if v == "" {
			continue
		}
		for _, p := range filepath.SplitList(v) {
			if p == "" {
				continue
			}
			if !filepath.IsAbs(p) && a.Dir != "" {
				p = shell.PhysicalJoin(a.Dir, p)
			}
			if p == os.DevNull || p == "/dev/null" {
				// The null device is empty by definition: pointing a CLI at it
				// (as sandboxes do) names no program, and no content can
				// arrive through it.
				continue
			}
			b, err := safefile.ReadFileMax(p, 1<<20)
			if err != nil {
				if !os.IsNotExist(err) {
					return k + " names " + p + ", which cannot be read, so what it runs is unknown"
				}
				continue
			}
			if credProcessRe.Match(b) {
				return k + " names " + p + ", which names a program to run (credential_process, exec)"
			}
		}
	}
	return ""
}
