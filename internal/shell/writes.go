package shell

import (
	"path"
	"slices"
	"strings"
)

// The write rules: for each program that writes, moves, removes or extracts
// into a path its words name, which words those are. The analyzer (an earlier
// step's writes make a later read unknown) and the classifier (a guard file or
// a state file in the way) both read them here, so there is one table, kept
// next to the allow-list entries.
//
// For a program with an allow-list entry (a prog), the rule reads the
// matcher's own parse: the operand or option value it names is the word the
// matcher took for it, so a plain call, which a protected tier allows, is
// judged on the same reading that made it plain. A call that is not plain is
// read leniently (an unlisted option is a flag, an unresolved word an
// operand), and a rule that names one operand (the destination of cp) names
// every one that may be it. Programs without an entry keep a rule over the
// words as they stand; they are never plain, so a protected tier asks for them
// whatever the rule finds.

// written is one path a call writes, and how.
type written struct {
	w Word
	k writeKind
}

// writeRules are the rules of the programs with an allow-list entry, read from
// the matcher's parse.
var writeRules = map[string]func(c parsed) []written{}

// wordRules are the rules of the programs without one, read from the words.
var wordRules = map[string]func(args []Word) []written{}

func each(ws []Word, k writeKind) []written {
	out := make([]written, 0, len(ws))
	for _, w := range ws {
		out = append(out, written{w, k})
	}
	return out
}

func lit(t string) Word { return Word{Text: t, Resolved: true, Prefix: t} }

// dest is the operand a copy writes into: the last one, or, for a call read
// leniently, every operand but the first (an unlisted option's value may
// stand after the destination).
func (c parsed) dest() []Word {
	switch {
	case len(c.ops) == 0:
		return nil
	case c.loose && len(c.ops) > 1:
		return c.ops[1:]
	}
	return c.ops[len(c.ops)-1:]
}

// writesOf returns what a call of program name writes.
func writesOf(name string, args []Word) []written {
	if f, p := writeRules[name], allowProgs[name]; f != nil && p != nil {
		c, why := p.parse(name, args)
		if why == "" {
			return f(c)
		}
		// Not plain: a program whose writing options are not listed has a
		// word rule for them; the others are read leniently.
		if g := wordRules[name]; g != nil {
			return g(args)
		}
		c, _ = p.read(name, args, true)
		return f(c)
	}
	if f := wordRules[name]; f != nil {
		return f(args)
	}
	return nil
}

// Writes returns the paths a call of program name writes, removes or changes,
// as its words name them (relative to the call's directory, unresolved words
// included). A directory it only creates (mkdir) is not among them: an empty
// directory replaces nothing, and the analyzer still records it. A program
// with no rule returns nothing; its output options are in OutputOpts.
func Writes(name string, args []Word) []Word {
	ws := writesOf(name, args)
	out := make([]Word, 0, len(ws))
	for _, w := range ws {
		if w.k != madeDir {
			out = append(out, w.w)
		}
	}
	return out
}

// Removes returns the words of Writes that the call only removes or moves
// away (rm's operands, mv's sources), and does not also write.
func Removes(name string, args []Word) []Word {
	ws := writesOf(name, args)
	var out []Word
	for _, w := range ws {
		if w.k != removed || !w.w.Resolved {
			continue
		}
		if slices.ContainsFunc(ws, func(o written) bool { return o.k != removed && o.k != madeDir && o.w.Text == w.w.Text }) {
			continue
		}
		out = append(out, w.w)
	}
	return out
}

// HasWriteRule reports whether name has a write rule.
func HasWriteRule(name string) bool { return writeRules[name] != nil || wordRules[name] != nil }

// URLBase is the file name a download of u is saved under ("" when u is not
// a URL or names no file).
func URLBase(u string) string {
	if !strings.Contains(u, "://") {
		return ""
	}
	u, _, _ = strings.Cut(u, "?")
	u, _, _ = strings.Cut(u, "#")
	b := path.Base(u)
	if b == "" || b == "." || b == "/" || strings.Contains(b, ":") {
		return ""
	}
	return b
}

// RemotePath reports whether p names a file on another host (s3://b/k,
// host:path), which a local write rule does not count.
func RemotePath(p string) bool {
	if strings.Contains(p, "://") {
		return true
	}
	host, _, ok := strings.Cut(p, ":")
	return ok && host != "" && !strings.Contains(host, "/")
}

var compressSuffixes = []string{".gz", ".bz2", ".xz", ".zst", ".Z", ".z", ".tgz"}

// inPlace: a compressor without -c replaces each operand with the compressed
// or expanded file beside it.
func inPlace(ops []Word, dec bool) []written {
	var out []written
	for _, w := range ops {
		out = append(out, written{w, wroteFile})
		if !dec || !w.Resolved {
			continue
		}
		for _, suf := range compressSuffixes {
			if strings.HasSuffix(w.Text, suf) {
				t := strings.TrimSuffix(w.Text, suf)
				if suf == ".tgz" {
					t += ".tar"
				}
				out = append(out, written{lit(t), wroteFile})
			}
		}
	}
	return out
}

func init() {
	writeRules["rm"] = func(c parsed) []written { return each(c.ops, removed) }
	writeRules["touch"] = func(c parsed) []written { return each(c.ops, changed) }
	writeRules["mkdir"] = func(c parsed) []written { return each(c.ops, madeDir) }
	writeRules["tee"] = func(c parsed) []written { return each(c.ops, wroteFile) }
	// The first operand of chmod is the mode, unless --reference gave it.
	writeRules["chmod"] = func(c parsed) []written {
		if c.has("--reference") || c.loose || len(c.ops) == 0 {
			return each(c.ops, changed)
		}
		return each(c.ops[1:], changed)
	}
	// cp writes into -t's directory or its last operand; mv and ln also
	// remove or replace what they are given (ln -f).
	copyRule := func(moves, mv bool) func(c parsed) []written {
		return func(c parsed) []written {
			var out []written
			if moves {
				// mv moves its sources away; ln -f replaces its link. Read
				// leniently, an operand may be an option's value or the
				// destination, so it is only changed.
				k := changed
				if mv && !c.loose {
					k = removed
				}
				out = each(c.ops, k)
			}
			if t, ok := c.val("-t", "--target-directory"); ok {
				return append(out, written{t, wroteTree})
			}
			if moves && len(c.ops) == 1 && c.ops[0].Resolved {
				// ln TARGET: a link named after it in the current directory.
				return append(out, written{lit(path.Base(c.ops[0].Text)), wroteTree})
			}
			if len(c.ops) < 2 {
				return out
			}
			return append(out, each(c.dest(), wroteTree)...)
		}
	}
	writeRules["cp"] = copyRule(false, false)
	writeRules["mv"] = copyRule(true, true)
	writeRules["ln"] = copyRule(true, false)
	// unzip extracts under -d, or here, unless it only lists, tests or prints.
	writeRules["unzip"] = func(c parsed) []written {
		if c.has("-l", "-v", "-t", "-p", "-c", "-z", "-Z") {
			return nil
		}
		if d, ok := c.val("-d"); ok {
			return []written{{d, wroteTree}}
		}
		return []written{{lit("."), wroteTree}}
	}
	// zip writes the archive (with .zip added when its name has no suffix);
	// -m removes what it adds.
	writeRules["zip"] = func(c parsed) []written {
		if len(c.ops) == 0 {
			return nil
		}
		if c.loose {
			return each(c.ops, wroteFile)
		}
		a := c.ops[0]
		out := []written{{a, wroteFile}}
		if a.Resolved && !strings.Contains(path.Base(a.Text), ".") {
			out = append(out, written{lit(a.Text + ".zip"), wroteFile})
		}
		if c.has("-m", "--move") {
			out = append(out, each(c.ops[1:], removed)...)
		}
		return out
	}
	writeRules["yq"] = func(c parsed) []written {
		if c.has("-i", "--inplace") {
			return each(c.ops, wroteFile)
		}
		return nil
	}
	// curl writes -o's file, or with -O the URL's file name here.
	writeRules["curl"] = func(c parsed) []written {
		var out []written
		for _, o := range append(append([]Word(nil), c.vals["-o"]...), c.vals["--output"]...) {
			if o.Text != "-" {
				out = append(out, written{o, wroteFile})
			}
		}
		if c.loose {
			// Read leniently: --output-dir and the like may have taken any
			// operand that is not a URL.
			for _, o := range c.ops {
				if !(o.Resolved && strings.Contains(o.Text, "://")) {
					out = append(out, written{o, wroteTree})
				}
			}
		}
		if c.has("-O", "--remote-name", "--remote-name-all", "-J", "--remote-header-name", "--output-dir") {
			out = append(out, written{lit("."), wroteTree})
			for _, u := range append(append([]Word(nil), c.ops...), c.vals["--url"]...) {
				if b := URLBase(u.Text); u.Resolved && b != "" {
					out = append(out, written{lit(b), wroteFile})
				}
			}
		}
		return out
	}
	// wget writes -O's file, or the URL's file name under -P or here.
	writeRules["wget"] = func(c parsed) []written {
		if o, ok := c.val("-O", "--output-document"); ok {
			if o.Text == "-" {
				return nil
			}
			return []written{{o, wroteFile}}
		}
		d, ok := c.val("-P", "--directory-prefix")
		if !ok {
			d = lit(".")
		}
		out := []written{{d, wroteTree}}
		for _, u := range c.ops {
			if b := URLBase(u.Text); u.Resolved && d.Resolved && b != "" {
				out = append(out, written{lit(path.Join(d.Text, b)), wroteFile})
			}
		}
		return out
	}
	gz := func(name string) func(c parsed) []written {
		return func(c parsed) []written {
			if c.has("-c", "--stdout", "--to-stdout", "-l", "--list", "-t", "--test") {
				return nil
			}
			return inPlace(c.ops, name == "gunzip" || c.has("-d", "--decompress", "--uncompress"))
		}
	}
	writeRules["gzip"] = gz("gzip")
	writeRules["gunzip"] = gz("gunzip")
	// uniq IN OUT and xxd IN OUT write the second operand (never plain).
	for _, n := range []string{"uniq", "xxd"} {
		writeRules[n] = func(c parsed) []written {
			if len(c.ops) < 2 {
				return nil
			}
			return each(c.ops[1:], wroteFile)
		}
	}

	// Programs without an entry.
	for _, n := range []string{"rmdir", "unlink", "srm"} {
		wordRules[n] = func(args []Word) []written { return each(operands(args), removed) }
	}
	for _, n := range []string{"shred", "truncate", "chown", "chattr"} {
		wordRules[n] = func(args []Word) []written { return each(operands(args), changed) }
	}
	for _, n := range []string{"install", "rsync", "ditto", "gcp", "gmv"} {
		n := n
		wordRules[n] = func(args []Word) []written {
			var out []written
			ops := operands(args)
			if n == "gmv" {
				out = each(ops, changed)
			}
			// Only install and GNU cp/mv take -t DIR; rsync's -t keeps times.
			if n != "rsync" && n != "ditto" {
				if t, ok := flagValue(args, 't', "--target-directory"); ok {
					return append(out, written{t, wroteTree})
				}
			}
			if len(ops) >= 2 && !(ops[len(ops)-1].Resolved && RemotePath(ops[len(ops)-1].Text)) {
				out = append(out, written{ops[len(ops)-1], wroteTree})
			}
			return out
		}
	}
	wordRules["dd"] = func(args []Word) []written {
		var out []written
		for _, w := range args {
			if v, ok := strings.CutPrefix(w.Text, "of="); ok {
				out = append(out, written{Word{Text: v, Resolved: w.Resolved, Prefix: v}, wroteFile})
			}
		}
		return out
	}
	for _, n := range []string{"tar", "bsdtar", "gtar"} {
		wordRules[n] = tarWrites
	}
	for _, n := range []string{"7z", "7za", "7zz", "7zr"} {
		wordRules[n] = func(args []Word) []written {
			ops := operands(args)
			if len(ops) == 0 || !ops[0].Resolved {
				return nil
			}
			switch ops[0].Text {
			case "x", "e":
				d := lit(".")
				for _, w := range args {
					if v, ok := strings.CutPrefix(w.Text, "-o"); ok && v != "" {
						d = Word{Text: v, Resolved: w.Resolved, Prefix: v}
					}
				}
				return []written{{d, wroteTree}}
			case "a", "u", "d", "rn":
				if len(ops) > 1 {
					return []written{{ops[1], wroteFile}}
				}
			}
			return nil
		}
	}
	wordRules["cpio"] = func(args []Word) []written {
		ops := operands(args)
		pass := hasFlag(args, "-p", "--pass-through") || clusterHas(args, 'p')
		if pass && len(ops) > 0 {
			return []written{{ops[len(ops)-1], wroteTree}}
		}
		if pass || hasFlag(args, "-i", "--extract") || clusterHas(args, 'i') {
			return []written{{lit("."), wroteTree}}
		}
		return nil
	}
	wordRules["patch"] = func(args []Word) []written {
		d, ok := flagValue(args, 'd', "--directory")
		if !ok {
			d = lit(".")
		}
		return append([]written{{d, wroteTree}}, each(operands(args), wroteFile)...)
	}
	for _, n := range []string{"bzip2", "bunzip2", "xz", "unxz", "zstd", "unzstd", "compress", "uncompress"} {
		n := n
		wordRules[n] = func(args []Word) []written {
			if hasFlag(args, "-c", "--stdout", "--to-stdout") || clusterHas(args, 'c') {
				return nil
			}
			return inPlace(operands(args), strings.HasPrefix(n, "un") || n == "bunzip2" || hasFlag(args, "-d", "--decompress", "--uncompress") || clusterHas(args, 'd'))
		}
	}
	for _, n := range []string{"openssl", "gpg", "age", "base64", "sort"} {
		n := n
		wordRules[n] = func(args []Word) []written {
			var out []written
			if n == "openssl" {
				if v, ok := flagValue(args, 0, "-out"); ok {
					out = append(out, written{v, wroteFile})
				}
			}
			if v, ok := flagValue(args, 'o', "--output"); ok && v.Text != "-" && n != "openssl" {
				out = append(out, written{v, wroteFile})
			}
			return out
		}
	}
	for _, n := range []string{"sed", "gsed", "perl", "ruby"} {
		wordRules[n] = func(args []Word) []written {
			if InPlaceEdit(args) {
				return each(operands(args), wroteFile)
			}
			return nil
		}
	}
	wordRules["find"] = findWrites
	for _, n := range []string{"scp", "rclone", "gsutil", "gcloud"} {
		n := n
		wordRules[n] = func(args []Word) []written { return remoteCopyWrites(n, args) }
	}
	wordRules["aws"] = func(args []Word) []written {
		if w := remoteCopyWrites("aws", args); w != nil {
			return w
		}
		// Every get-* call that saves its answer takes the file as the last
		// word (s3api get-object, apigateway get-export, glacier
		// get-job-output), and --kubeconfig names the file eks
		// update-kubeconfig rewrites.
		var out []written
		ops := operands(args)
		if len(ops) >= 3 && ops[1].Resolved && strings.HasPrefix(ops[1].Text, "get-") {
			out = append(out, written{ops[len(ops)-1], wroteFile})
		}
		if v, ok := flagValue(args, 0, "--kubeconfig"); ok {
			out = append(out, written{v, wroteFile})
		}
		return out
	}
	wordRules["git"] = func(args []Word) []written {
		// clone, checkout, restore, apply, pull, ... rewrite the tree.
		ops := operands(args)
		if len(ops) > 0 && toSet("clone", "checkout", "switch", "restore", "apply", "am", "pull", "merge", "rebase", "reset", "stash", "worktree", "cherry-pick", "revert")[ops[0].Text] {
			return []written{{lit("."), wroteContents}}
		}
		return nil
	}
	// sort and base64 have an entry, but -o is not among its options: a
	// plain call writes nothing, and a call with -o is read by the word rule.
	for _, n := range []string{"sort", "base64"} {
		writeRules[n] = func(c parsed) []written { return nil }
	}
}

// operands are the words that are not options (words after -- included),
// read without knowing which options take a value.
func operands(args []Word) []Word {
	var out []Word
	end := false
	for _, w := range args {
		t := w.Text
		switch {
		case end:
			out = append(out, w)
		case t == "--" && w.Resolved:
			end = true
		case !strings.HasPrefix(t, "-") || t == "-":
			out = append(out, w)
		}
	}
	return out
}

// flagValue returns the value of an option given as "-x v", "-xv", "--long v"
// or "--long=v", also at the end of a cluster of short options ("-so v").
// long may be a single-dash name (openssl -out).
func flagValue(args []Word, short byte, long string) (Word, bool) {
	for i, w := range args {
		t := w.Text
		if t == "--" {
			break
		}
		if long != "" {
			if v, ok := strings.CutPrefix(t, long+"="); ok {
				return Word{Text: v, Resolved: w.Resolved, Prefix: v}, true
			}
			if t == long && i+1 < len(args) {
				return args[i+1], true
			}
		}
		if short != 0 && len(t) >= 2 && t[0] == '-' && t[1] != '-' {
			if j := strings.IndexByte(t[1:], short); j >= 0 {
				if rest := t[j+2:]; rest != "" {
					return Word{Text: rest, Resolved: w.Resolved, Prefix: rest}, true
				}
				if i+1 < len(args) {
					return args[i+1], true
				}
			}
		}
	}
	return Word{}, false
}

func clusterHas(args []Word, c byte) bool {
	for _, w := range args {
		t := w.Text
		if t == "--" {
			return false
		}
		if len(t) > 1 && t[0] == '-' && t[1] != '-' && strings.IndexByte(t[1:], c) >= 0 {
			return true
		}
	}
	return false
}

// tarWrites reads a tar command as tar does: short options in a cluster take
// their values from the following words in order (tar -cfC out.tar dir: f
// takes out.tar and C takes dir), the first word may be a cluster without a
// dash, and the long options with a value take the next word unless they
// carry =. Extraction writes under every -C directory, or here; creating,
// appending or updating writes the -f archive.
func tarWrites(args []Word) []written {
	valued := "CfITXFKLbgNV"
	longValued := toSet("--directory", "--file", "--files-from", "--exclude-from", "--transform", "--use-compress-program", "--to-command",
		"--owner", "--group", "--mtime", "--sort", "--format", "--warning", "--exclude", "--strip-components", "--newer", "--after-date",
		"--blocking-factor", "--record-size", "--listed-incremental", "--label", "--volno-file", "--info-script", "--new-volume-script", "--checkpoint-action")
	var extract, create bool
	var dirs, files []Word
	take := func(opt string, v Word) {
		switch opt {
		case "C", "--directory":
			dirs = append(dirs, v)
		case "f", "--file":
			files = append(files, v)
		}
	}
	for i := 0; i < len(args); i++ {
		w := args[i]
		t := w.Text
		switch {
		case t == "--":
			i = len(args)
		case t == "--extract" || t == "--get":
			extract = true
		case t == "--create" || t == "--append" || t == "--update" || t == "--concatenate" || t == "--catenate" || t == "--delete":
			create = true
		case strings.HasPrefix(t, "--"):
			k, v, eq := strings.Cut(t, "=")
			if eq {
				take(k, Word{Text: v, Resolved: w.Resolved, Prefix: v})
			} else if longValued[k] && i+1 < len(args) {
				i++
				take(k, args[i])
			}
		case strings.HasPrefix(t, "-") && len(t) > 1 || i == 0 && t != "" && !strings.ContainsAny(t, "/."):
			cluster := strings.TrimPrefix(t, "-")
			var pending []string
			for j := 0; j < len(cluster); j++ {
				ch := cluster[j]
				switch ch {
				case 'x':
					extract = true
				case 'c', 'r', 'u', 'A':
					create = true
				}
				if strings.IndexByte(valued, ch) < 0 {
					continue
				}
				if strings.HasPrefix(t, "-") && len(pending) == 0 && j+1 < len(cluster) {
					// -Cdir, -fout.tar: the rest of the word is the value.
					v := cluster[j+1:]
					take(string(ch), Word{Text: v, Resolved: w.Resolved, Prefix: v})
					break
				}
				pending = append(pending, string(ch))
			}
			for _, opt := range pending {
				if i+1 < len(args) {
					i++
					take(opt, args[i])
				}
			}
		}
	}
	var out []written
	if extract {
		if len(dirs) == 0 {
			out = append(out, written{lit("."), wroteTree})
		}
		out = append(out, each(dirs, wroteTree)...)
	}
	if create {
		for _, f := range files {
			if f.Text != "-" {
				out = append(out, written{f, wroteFile})
			}
		}
	}
	return out
}

// findWrites: find removes what it finds under its starting points with
// -delete or a remover it runs (-exec rm), and writes the files -fprint,
// -fprint0, -fprintf and -fls name.
func findWrites(args []Word) []written {
	var starts []Word
	i := 0
	for ; i < len(args); i++ {
		t := args[i].Text
		switch {
		case t == "-P" || t == "-H" || t == "-L" || t == "-s" || t == "-x" || t == "-E" || t == "-X" || t == "-d" || strings.HasPrefix(t, "-O") && len(t) > 2:
			continue
		case t == "-D" || t == "-f":
			if t == "-f" && i+1 < len(args) {
				starts = append(starts, args[i+1])
			}
			i++
			continue
		}
		if strings.HasPrefix(t, "-") || t == "(" || t == "!" {
			break
		}
		starts = append(starts, args[i])
	}
	var out []written
	removes, onlyRemoves := false, true
	for ; i < len(args); i++ {
		t := args[i].Text
		switch t {
		case "-delete":
			removes = true
		case "-exec", "-execdir", "-ok", "-okdir":
			if i+1 < len(args) && execWriters[ProgName(args[i+1].Text)] {
				removes = true
				// rm and the like only remove what find gives them;
				// mv, chmod and ln also move or change it.
				if !execRemovers[ProgName(args[i+1].Text)] {
					onlyRemoves = false
				}
			}
		case "-fprint", "-fprint0", "-fls":
			if i+1 < len(args) {
				out = append(out, written{args[i+1], wroteFile})
			}
		case "-fprintf":
			if i+1 < len(args) {
				out = append(out, written{args[i+1], wroteFile})
			}
		}
	}
	if removes {
		if len(starts) == 0 {
			starts = []Word{lit(".")}
		}
		k := changed
		if onlyRemoves {
			k = removed
		}
		out = append(out, each(starts, k)...)
	}
	return out
}

// execWriters are the removers: run under find -exec, they change what find
// found. Another program find runs is an invocation of its own when the
// analysis follows it.
var execRemovers = toSet("rm", "rmdir", "srm", "unlink")

var execWriters = toSet("rm", "rmdir", "srm", "unlink", "shred", "mv", "chmod", "chown", "chattr", "truncate", "ln")

// RemoteCopy reports whether a command copies between a remote store and
// local files, with the destination last: scp, rclone copy, aws s3 cp,
// gsutil cp, gcloud storage cp.
func RemoteCopy(name string, args []Word) bool {
	var sub []string
	for _, w := range args {
		if !strings.HasPrefix(w.Text, "-") {
			sub = append(sub, w.Text)
		}
	}
	at := func(i int, ws ...string) bool {
		if len(sub) <= i {
			return false
		}
		for _, x := range ws {
			if sub[i] == x {
				return true
			}
		}
		return false
	}
	switch name {
	case "scp":
		return true
	case "rclone":
		return at(0, "copy", "copyto", "sync", "move", "moveto", "copyurl")
	case "aws":
		return at(0, "s3") && at(1, "cp", "mv", "sync")
	case "gsutil":
		return at(0, "cp", "mv", "rsync")
	case "gcloud":
		return at(0, "storage") && at(1, "cp", "mv", "rsync")
	}
	return false
}

// remoteCopyWrites: the destination of a remote copy, when it is local.
func remoteCopyWrites(name string, args []Word) []written {
	if !RemoteCopy(name, args) {
		return nil
	}
	ops := operands(args)
	if len(ops) < 2 {
		return nil
	}
	d := ops[len(ops)-1]
	if d.Resolved && RemotePath(d.Text) {
		return nil
	}
	return []written{{d, wroteTree}}
}
