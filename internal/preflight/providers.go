package preflight

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
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

// programData are data sources that run a program while Terraform plans:
// the external provider's, the shell providers' and local_command.
var programData = regexp.MustCompile(`(?m)^\s*data\s+"?(external|local_command|shell_[a-z_]+)"?\s`)

// RunsPrograms reports a data source that runs a program during plan, in
// dir's configuration, the local modules it calls, and the modules init
// downloaded into dataDir. "" when there is none. A configuration too large
// to read in full counts as one that may.
func RunsPrograms(dir, dataDir string) string {
	seen := map[string]bool{}
	files := 0
	var scan func(d string, depth int) string
	scan = func(d string, depth int) string {
		d = filepath.Clean(d)
		if seen[d] || depth > 10 {
			return ""
		}
		seen[d] = true
		ents, err := os.ReadDir(d)
		if err != nil {
			return ""
		}
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() || !(strings.HasSuffix(n, ".tf") || strings.HasSuffix(n, ".tf.json")) {
				continue
			}
			if files++; files > 2000 {
				return "more configuration files than applygate reads"
			}
			b, err := os.ReadFile(filepath.Join(d, n))
			if err != nil {
				return "a configuration file that cannot be read: " + filepath.Join(d, n)
			}
			s := string(b)
			if strings.HasSuffix(n, ".json") {
				if strings.Contains(s, `"data"`) && (strings.Contains(s, `"external"`) || strings.Contains(s, `"local_command"`) || strings.Contains(s, `"shell_`)) {
					return "a data source that runs a program in " + filepath.Join(d, n)
				}
				continue
			}
			if m := programData.FindStringSubmatch(s); m != nil {
				return "data \"" + m[1] + "\" in " + filepath.Join(d, n) + " runs a program during plan"
			}
			for _, src := range localSource.FindAllStringSubmatch(s, -1) {
				if why := scan(filepath.Join(d, src[1]), depth+1); why != "" {
					return why
				}
			}
		}
		return ""
	}
	if why := scan(dir, 0); why != "" {
		return why
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

var localSource = regexp.MustCompile(`(?m)^\s*source\s*=\s*"(\.\.?/[^"]*)"`)
