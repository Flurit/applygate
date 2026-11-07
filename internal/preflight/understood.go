package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// The positive rule for what Terraform loads.
//
// The scans in RunsPrograms and RunsBackendPrograms are lists of things known
// to run a program: each new file kind, option or module source that was not
// on a list was an allow (round 9: .tfquery.hcl, -backend-config, a module
// init fetches, graph -type=plan, a file over the size cap). Understood turns
// it around. A configuration is plain only when everything it makes Terraform
// load is both understood and pinned locally:
//
//   - every configuration file in the directory and in every module it calls
//     reads and parses within the size cap, whatever its extension;
//   - every module source is a literal that is a local path, or a remote
//     source the module manifest says init already installed (init would
//     otherwise download code that nothing has read);
//   - every provider is one whose attributes this package models (a closed
//     list), and is in the lock file;
//   - the lock file that vouches for installed providers is on the upstream
//     branch (a repository the agent made, or one with no upstream, vouches
//     for nothing).
//
// Anything else is not plain, so it asks in a protected tier.

// understoodProviders are the registry providers whose attributes that name a
// program or a credentials file are the ones runsIn models. A provider
// outside the list (the external provider, a third-party one whose schema may
// start a command) is not understood.
var understoodProviders = map[string]bool{
	"hashicorp/aws": true, "hashicorp/awscc": true, "hashicorp/google": true, "hashicorp/google-beta": true,
	"hashicorp/azurerm": true, "hashicorp/azuread": true, "azure/azapi": true, "hashicorp/kubernetes": true,
	"hashicorp/helm": true, "hashicorp/random": true, "hashicorp/null": true, "hashicorp/time": true,
	"hashicorp/tls": true, "hashicorp/archive": true, "hashicorp/local": true, "hashicorp/http": true,
	"hashicorp/dns": true, "hashicorp/cloudinit": true, "hashicorp/template": true,
}

// Understood reports why the configuration terraform or tofu would load in
// dir (with the module and provider state in dataDir) is not fully understood
// and pinned locally, or "".
func Understood(ctx context.Context, dir, dataDir string) string {
	manifest := map[string]string{} // module source -> installed directory
	if b, err := os.ReadFile(filepath.Join(dataDir, "modules", "modules.json")); err == nil {
		var m struct {
			Modules []struct{ Source, Dir string }
		}
		if json.Unmarshal(b, &m) != nil {
			return "the module manifest " + filepath.Join(dataDir, "modules", "modules.json") + " cannot be read"
		}
		for _, mod := range m.Modules {
			d := mod.Dir
			if d != "" && !filepath.IsAbs(d) {
				d = filepath.Join(dir, d)
			}
			manifest[mod.Source] = filepath.Clean(d)
		}
	} else if !os.IsNotExist(err) {
		return "the module manifest " + filepath.Join(dataDir, "modules", "modules.json") + " cannot be read"
	}
	lock := map[string]bool{}
	if b, err := readCapped(filepath.Join(dir, ".terraform.lock.hcl"), MaxConfigFile); err == nil {
		for _, m := range lockProvider.FindAllSubmatch(b, -1) {
			a := strings.ToLower(string(m[1]))
			if strings.Count(a, "/") == 1 {
				a = "registry.terraform.io/" + a
			}
			lock[a] = true
		}
	} else if !os.IsNotExist(err) {
		return "the lock file cannot be read: " + err.Error()
	}
	used := map[string]string{} // provider address -> where it is used
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
			return "a directory that cannot be read: " + d
		}
		var parsed []*hcl.File
		for _, e := range ents {
			if e.IsDir() || !configName(e.Name()) {
				continue
			}
			if files++; files > 2000 {
				return "more configuration files than applygate reads"
			}
			f := filepath.Join(d, e.Name())
			file, why := readConfig(f)
			if why != "" {
				return why
			}
			parsed = append(parsed, file)
		}
		decl := map[string]string{} // local name -> source
		for _, file := range parsed {
			top, _, _ := file.Body.PartialContent(terraformSchema)
			for _, tb := range top.Blocks {
				rp, _, _ := tb.Body.PartialContent(requiredSchema)
				for _, b := range rp.Blocks {
					attrs, _ := b.Body.JustAttributes()
					for name, a := range attrs {
						decl[name] = providerSource(name, a)
					}
				}
			}
		}
		for _, file := range parsed {
			impl, _, _ := file.Body.PartialContent(runsTopSchema)
			for _, b := range impl.Blocks {
				name := ""
				switch b.Type {
				case "resource", "data":
					name, _, _ = strings.Cut(b.Labels[0], "_")
				case "provider":
					name = b.Labels[0]
				}
				if name == "" || name == "terraform" {
					continue
				}
				src, ok := decl[name]
				if !ok {
					src = "registry.terraform.io/hashicorp/" + name
				}
				used[src] = d
			}
			mods, _, _ := file.Body.PartialContent(moduleSchema)
			for _, mb := range mods.Blocks {
				attrs, _ := mb.Body.JustAttributes()
				a, ok := attrs["source"]
				if !ok {
					return "module " + mb.Labels[0] + " in " + d + " has no source"
				}
				src, lit := literal(a.Expr)
				if !lit {
					return "module " + mb.Labels[0] + " in " + d + " has a source that is not a literal"
				}
				if strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") {
					if why := scan(filepath.Join(d, src), depth+1); why != "" {
						return why
					}
					continue
				}
				inst, ok := manifest[src]
				if !ok {
					return "module " + mb.Labels[0] + " in " + d + " comes from " + src + ", which is not installed locally (init would download code that has not been read)"
				}
				if why := scan(inst, depth+1); why != "" {
					return why
				}
			}
		}
		return ""
	}
	if why := scan(dir, 0); why != "" {
		return why
	}
	// terraform test and stacks read their own files from tests/.
	if why := scan(filepath.Join(dir, "tests"), 1); why != "" {
		return why
	}
	installed := map[string]bool{}
	root := filepath.Join(dataDir, "providers")
	pdirs, perr := providerDirs(root)
	if perr != nil {
		return "the installed providers cannot be listed: " + perr.Error()
	}
	for _, pd := range pdirs {
		rel, _ := filepath.Rel(root, pd)
		if parts := strings.Split(filepath.ToSlash(rel), "/"); len(parts) >= 3 {
			installed[strings.ToLower(strings.Join(parts[:3], "/"))] = true
		}
	}
	for src, where := range used {
		rest := strings.TrimPrefix(src, "registry.terraform.io/")
		if rest == src || !understoodProviders[rest] {
			return "provider " + src + " (used in " + where + ") is not one applygate understands"
		}
		// A provider that is not installed starts nothing (init would fetch it,
		// and InitSafe asks the lock file about that); one that is installed
		// must be locked.
		if installed[src] && !lock[src] {
			return "provider " + src + " (used in " + where + ") is installed but not in the lock file"
		}
	}
	return ""
}

// providerSource is the registry address a required_providers entry names.
func providerSource(name string, a *hcl.Attribute) string {
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
	src = strings.ToLower(src)
	switch strings.Count(src, "/") {
	case 1:
		src = "registry.terraform.io/" + src
	case 0:
		src = "registry.terraform.io/hashicorp/" + src
	}
	return src
}

// PinnedByUpstream reports why the providers installed under dataDir are not
// vouched for by a lock file the upstream branch holds: with providers
// installed, a repository with no upstream branch (one the agent created with
// git init, a detached HEAD) vouches for nothing, because its HEAD is whatever
// was committed last. nil when no provider is installed.
func PinnedByUpstream(ctx context.Context, dir, dataDir string) error {
	dirs, err := providerDirs(filepath.Join(dataDir, "providers"))
	if err != nil {
		return fmt.Errorf("cannot list the installed providers: %v", err)
	}
	if len(dirs) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := gitCommand(ctx, dir, "rev-parse", "--verify", "--quiet", "@{upstream}").Run(); err != nil {
		return fmt.Errorf("providers are installed but the repository has no upstream branch, so nothing outside the working copy vouches for the lock file")
	}
	return nil
}
