package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/hook"
	"github.com/Flurit/applygate/internal/scan"
)

// cmdScan reports how exposed the machine's infrastructure is to its coding
// agents: what the boundary checks find, then what applygate would have
// decided on the tool calls Claude Code and Codex already recorded in their
// session files, with the rules and config of today. It needs no hook and
// changes nothing: the calls are not run, the decision log is not written,
// and the model judge and saved plans are not asked. The cloud is asked
// only with --boundary, and then only what the credentials here can do.
func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	days := fs.Int("days", 30, "how many days back to read; 0 reads every session the agents kept")
	dir := fs.String("dir", "", "only calls made in this directory or under it")
	all := fs.Bool("all", false, "list every call it would block or ask about, not the latest 10 of each")
	asJSON := fs.Bool("json", false, "print one JSON object per judged call instead of the report")
	boundary := fs.Bool("boundary", false, "also ask AWS, Google Cloud, Azure and the clusters what the credentials here can do (read-only), as applygate doctor --boundary does")
	share := fs.Bool("share", false, "print counts only, with no command, path or name, to send to someone else")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *days < 0 || *asJSON && (*share || *boundary) {
		fmt.Fprintln(stderr, "usage: applygate scan [--days N] [--dir DIR] [--boundary] [--all | --share]\n       applygate scan [--days N] [--dir DIR] --json")
		return 2
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "applygate: no home directory:", err)
		return 1
	}
	under := ""
	if *dir != "" {
		if under, err = filepath.Abs(*dir); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if r, err := filepath.EvalSymlinks(under); err == nil {
			under = r
		}
	}
	var since time.Time
	if *days > 0 {
		since = time.Now().AddDate(0, 0, -*days)
	}
	env := hook.EnvMap()
	rp := &replayer{env: env, full: *asJSON}

	// The session files are read in order by one goroutine; the calls are
	// judged by several, since a verdict costs some 15 ms and a month of
	// sessions holds thousands of them. seq keeps the order of reading.
	type job struct {
		seq int
		c   scan.Call
	}
	type result struct {
		seq   int
		row   scan.Row
		state int
	}
	jobs, results := make(chan job, 64), make(chan result, 64)
	var wg sync.WaitGroup
	for range min(runtime.NumCPU(), 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				row, state := rp.judge(j.c)
				results <- result{j.seq, row, state}
			}
		}()
	}
	sum := scan.Summary{}
	var seqs []int
	var done atomic.Int64
	collected := make(chan struct{})
	go func() {
		defer close(collected)
		for r := range results {
			done.Add(1)
			switch r.state {
			case unchecked:
				sum.Unchecked++
			case gone:
				sum.Gone++
			default:
				sum.Rows = append(sum.Rows, r.row)
				seqs = append(seqs, r.seq)
			}
		}
	}()
	// The boundary checks do not depend on the sessions: they run beside the
	// reading. The JSON output is the judged calls and nothing else.
	exposed := make(chan *scan.Exposure, 1)
	if *asJSON {
		exposed <- nil
	} else {
		go func() { exposed <- exposure(*boundary) }()
	}
	stop := progress(stderr, &done)
	n := 0
	sum.Stats = scan.Walk(scan.Sources(home, env), since, func(c scan.Call) {
		if under != "" && !isUnder(c.Dir(), under) {
			return
		}
		jobs <- job{n, c}
		n++
	})
	close(jobs)
	wg.Wait()
	close(results)
	<-collected
	sum.Exposure = <-exposed
	stop()
	sum.Stats.Calls = n
	sort.Sort(bySeq{sum.Rows, seqs})

	if *asJSON {
		enc := json.NewEncoder(stdout)
		for _, r := range sum.Rows {
			_ = enc.Encode(r)
		}
		return 0
	}
	opt := scan.RenderOptions{Version: hook.Version, Days: *days, Home: home, All: *all}
	if *share {
		sum.RenderShare(stdout, opt)
		return 0
	}
	sum.Render(stdout, opt)
	return 0
}

// exposure makes the boundary checks of applygate doctor --boundary for the
// report. With audit false it asks nothing of the cloud or the clusters.
func exposure(audit bool) *scan.Exposure {
	wd, _ := os.Getwd()
	cfg, err := config.Load(config.UserPath(), wd)
	if err != nil {
		return &scan.Exposure{Error: "config: " + err.Error()}
	}
	r := evalBoundaryWith(cfg, audit)
	x := &scan.Exposure{Audited: r.audited, Level: r.reached, CredsOK: r.credsOK, CredsFail: r.credsFail, CredsUnchecked: r.credsUnchecked, CredsUnplaced: r.credsUnplaced}
	for _, c := range r.checks {
		if c.level > 0 {
			x.Checks = append(x.Checks, scan.Check{Level: c.level, Status: c.status, Text: c.text})
		}
	}
	return x
}

type bySeq struct {
	rows []scan.Row
	seqs []int
}

func (b bySeq) Len() int           { return len(b.rows) }
func (b bySeq) Less(i, j int) bool { return b.seqs[i] < b.seqs[j] }
func (b bySeq) Swap(i, j int) {
	b.rows[i], b.rows[j] = b.rows[j], b.rows[i]
	b.seqs[i], b.seqs[j] = b.seqs[j], b.seqs[i]
}

// progress writes a count to a terminal while the scan runs, and returns
// the function that ends it. Output that is not a terminal gets nothing.
func progress(w io.Writer, done *atomic.Int64) func() {
	f, ok := w.(*os.File)
	if !ok || !isTerminal(f) {
		return func() {}
	}
	quit, ended := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(ended)
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		shown := false
		for {
			select {
			case <-quit:
				if shown {
					fmt.Fprint(f, "\r\033[K")
				}
				return
			case <-t.C:
				fmt.Fprintf(f, "\rreading sessions: %d calls judged", done.Load())
				shown = true
			}
		}
	}()
	return func() { close(quit); <-ended }
}

func isUnder(p, root string) bool {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	rel, err := filepath.Rel(root, p)
	return err == nil && !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

const (
	judged = iota
	unchecked
	gone
)

// replayer judges recorded calls through the hook's own path. It remembers
// the answer for a call it has seen: agents repeat commands, and the files a
// verdict reads are the same within one scan.
type replayer struct {
	env  map[string]string
	full bool     // keep every row's text (--json)
	memo sync.Map // key -> *memoed
	dirs sync.Map // dir -> dirInfo
}

type memoed struct {
	once  sync.Once
	entry decisionlog.Entry
	ok    bool
}

type dirInfo struct {
	exists, noConfig bool
	repo             string
}

func (rp *replayer) dir(dir string) dirInfo {
	if dir == "" {
		return dirInfo{}
	}
	if v, ok := rp.dirs.Load(dir); ok {
		return v.(dirInfo)
	}
	var di dirInfo
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		di.exists = true
		// No trusted repository config covers the directory: the user
		// config or the defaults judge what runs there.
		cfg, err := config.Load(config.UserPath(), dir)
		di.noConfig = err == nil && cfg.Root == ""
		di.repo = repoRoot(dir)
	}
	rp.dirs.Store(dir, di)
	return di
}

func (rp *replayer) judge(c scan.Call) (scan.Row, int) {
	// A verdict reads the directory: its config, its Terraform files, its
	// git state. With the directory gone there is nothing to judge against.
	ran := rp.dir(c.Dir())
	if !ran.exists || !rp.dir(c.Cwd).exists {
		return scan.Row{}, gone
	}
	a, err := hook.ForAgent(c.Agent)
	if err != nil {
		return scan.Row{}, unchecked
	}
	// The session is part of the hook input but not of the verdict.
	key := sha256.Sum256([]byte(c.Agent + "\x00" + c.Tool + "\x00" + c.Cwd + "\x00" + string(c.Input)))
	v, _ := rp.memo.LoadOrStore(key, &memoed{})
	m := v.(*memoed)
	m.once.Do(func() {
		hook.Run(a, bytes.NewReader(c.HookInput()), hook.Options{
			UserConfig: config.UserPath(),
			NoLog:      true,
			Offline:    true,
			Env:        rp.env,
			Timeout:    10 * time.Second,
			// A past plan is not there to read, and reading one starts the
			// provider plugins of its directory: scan never does.
			PlanJSON: func(string, string, string) ([]byte, error) {
				return nil, errors.New("applygate scan does not read saved plans")
			},
			Record: func(e decisionlog.Entry) { m.entry, m.ok = e, true },
		})
	})
	if !m.ok {
		return scan.Row{}, unchecked
	}
	return scan.NewRow(c, m.entry, ran.repo, ran.noConfig, rp.full), judged
}

// repoRoot is the nearest directory at or above dir that holds .git (a
// work tree's root), or dir when there is none.
func repoRoot(dir string) string {
	for d := dir; ; {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		up := filepath.Dir(d)
		if up == d {
			return dir
		}
		d = up
	}
}
