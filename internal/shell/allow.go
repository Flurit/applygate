package shell

import (
	"regexp"
	"strings"
)

// A prog is the closed description of the plain calls of one program: the
// options it may be given are listed by exact name, and a call with an option
// that is not listed is not plain (an ask in a protected tier). This replaces
// "takes any arguments" and the deny lists that name the options that run a
// program or write a file: those lose to every spelling their author did not
// think of, while a list of what is understood can only be wrong by listing
// too much, which the conformance test (allow_conformance_test.go) checks by
// running each entry.
//
// Rules the matcher applies to every program:
//   - option names are exact: no GNU abbreviation (--recur), no BSD
//     option-after-operand difference (a word that starts with a dash is an
//     option wherever it stands, until --);
//   - a word that cannot be resolved and could be an option (it starts with a
//     dash, or has no literal prefix at all) is not plain, unless the program
//     lists no option that writes or runs anything (loose);
//   - an option that writes a file is listed only when the analysis judges
//     that write itself (cp -t, ln -t, mv -t); otherwise it is absent.
type prog struct {
	flags  map[string]bool // options without a value
	vals   map[string]bool // options with one value (a pattern, number, format or file read)
	optVal map[string]bool // long options with an optional =value
	num    bool            // -N (digits only) is an option (head -5, gzip -9)
	loose  bool            // an unresolved word may be left alone: no listed or real option makes a path or program
	maxOps int             // at most this many operands; -1 is any number
	ops    func(ops []Word) string
	need   func(seen map[string]bool) string // a rule over the options seen
	opWord func(t string) bool               // a word that starts with a dash but is an operand (a chmod mode)
	once   map[string]bool                   // options that may appear once (the analysis judges one output file per call)
	valOK  func(opt string, v Word) string   // a rule over the value of an option
	writes map[string]bool                   // options whose value is a file the analysis judges as written (the conformance test expects it)
}

// allowProgs are the programs described by a prog, by name (the conformance
// test runs every entry).
var allowProgs = map[string]*prog{}

func allow(name string, p *prog) {
	allowProgs[name] = p
	shapes[name] = p.shape(name)
}

func opts(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(s) {
		m[f] = true
	}
	return m
}

// newProg builds a prog from space-separated lists.
func newProg(flags, vals string) *prog {
	return &prog{flags: opts(flags), vals: opts(vals), optVal: map[string]bool{}, maxOps: -1}
}

func (p *prog) withOptVal(s string) *prog { p.optVal = opts(s); return p }
func (p *prog) withNum() *prog            { p.num = true; return p }
func (p *prog) withLoose() *prog          { p.loose = true; return p }
func (p *prog) withOnce(s string) *prog   { p.once = opts(s); return p }
func (p *prog) withWrites(s string) *prog { p.writes = opts(s); return p }
func (p *prog) withValOK(f func(string, Word) string) *prog {
	p.valOK = f
	return p
}
func (p *prog) withMaxOps(n int) *prog { p.maxOps = n; return p }

var digitsRE = regexp.MustCompile(`^[0-9]+$`)

// shape is the program's check, as an entry of shapes.
func (p *prog) shape(name string) shape {
	return func(args []Word, _ Invocation) string { return p.check(name, args) }
}

// check reports why a call of name with args is not plain ("" when it is).
func (p *prog) check(name string, args []Word) string {
	seen := map[string]bool{}
	var ops []Word
	endOpts := false
	// use records an option and checks the rules over it and its value.
	use := func(opt string, v *Word) string {
		if p.once[opt] && seen[opt] {
			return "the option " + opt + " more than once"
		}
		seen[opt] = true
		if v != nil && p.valOK != nil {
			return p.valOK(opt, *v)
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		w := args[i]
		t := optText(w)
		if endOpts {
			ops = append(ops, w)
			continue
		}
		if t == "--" && w.Resolved {
			endOpts = true
			continue
		}
		// An unresolved word is read by its literal prefix: -var=x=$Y names -var.
		knownName := !w.Resolved && strings.HasPrefix(t, "-") && strings.Contains(t, "=")
		if !w.Resolved && (t == "" || strings.HasPrefix(t, "-")) && !knownName && !(p.loose && !strings.HasPrefix(t, "-")) {
			return "a word that cannot be resolved may be an option of " + name
		}
		if !strings.HasPrefix(t, "-") || t == "-" || p.opWord != nil && w.Resolved && p.opWord(t) {
			ops = append(ops, w)
			continue
		}
		if strings.HasPrefix(t, "--") {
			k, _, hasEq := strings.Cut(t, "=")
			switch {
			case p.flags[k]:
				if hasEq {
					return "the option " + k + " with a value"
				}
				if why := use(k, nil); why != "" {
					return why
				}
			case p.optVal[k]:
				seen[k] = true
			case p.vals[k]:
				v := Word{Text: strings.TrimPrefix(w.Text, k+"="), Resolved: w.Resolved}
				if !hasEq {
					if i+1 >= len(args) {
						return "the option " + k + " without its value"
					}
					i++
					v = args[i]
				}
				if why := use(k, &v); why != "" {
					return why
				}
			default:
				return "the option " + k + " of " + name
			}
			continue
		}
		// One dash. A whole name first (find, go and Go-style programs take
		// -name, -toolexec), then a number, then a cluster of letters.
		if p.flags[t] {
			if why := use(t, nil); why != "" {
				return why
			}
			continue
		}
		if p.vals[t] {
			if i+1 >= len(args) {
				return "the option " + t + " without its value"
			}
			i++
			if why := use(t, &args[i]); why != "" {
				return why
			}
			continue
		}
		if p.num && digitsRE.MatchString(t[1:]) {
			continue
		}
		// -name=value, as Go's flag package and Terraform read them.
		if k, v, eq := strings.Cut(t, "="); eq && len(k) > 2 && (p.flags[k] || p.vals[k]) {
			val := Word{Text: v, Resolved: w.Resolved}
			if why := use(k, map[bool]*Word{true: &val, false: nil}[p.vals[k]]); why != "" {
				return why
			}
			continue
		}
		for j := 1; j < len(t); j++ {
			c := "-" + string(t[j])
			switch {
			case p.flags[c]:
				if why := use(c, nil); why != "" {
					return why
				}
				continue
			case p.vals[c]:
				v := Word{Text: w.Text[j+1:], Resolved: w.Resolved}
				if j+1 == len(t) {
					if i+1 >= len(args) {
						return "the option " + c + " without its value"
					}
					i++
					v = args[i]
				}
				if why := use(c, &v); why != "" {
					return why
				}
			case p.num && digitsRE.MatchString(t[j:]):
			default:
				return "the option " + c + " of " + name
			}
			break
		}
	}
	if p.maxOps >= 0 && len(ops) > p.maxOps {
		return "more than " + itoa(p.maxOps) + " operands of " + name
	}
	if p.ops != nil {
		if why := p.ops(ops); why != "" {
			return why
		}
	}
	if p.need != nil {
		return p.need(seen)
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// inert are the programs that keep "any arguments": every option the program
// has, listed or not, only reads files or prints, and none runs a program or
// writes a file. Each is audited against the GNU and BSD manual pages; a new
// name needs the same audit (allow_test.go asserts this list and the shapes
// that are nil are the same set). A program with a write-capable or
// exec-capable option never belongs here: it gets a prog.
var inert = toSet(
	// builtins and trivial
	"pwd", "echo", "true", "false", "test", "[", "exit", "unset", "sleep", "which", "type",
	// readers of files and directories
	"ls", "cat", "head", "tail", "wc", "grep", "egrep", "cut", "tr", "cmp", "stat", "df", "du",
	"basename", "dirname", "realpath", "readlink", "column", "od", "jq", "nl", "fold", "comm", "join", "paste",
	"sha256sum", "shasum", "md5sum", "seq", "id", "whoami", "uname", "printenv",
	// linters that only read
	"shellcheck",
)

// writers: the files these write are the operands (and -t's directory),
// which the classifier judges; the options listed here change how they do it.
func init() {
	// rm deletes its operands; --no-preserve-root is left out.
	allow("rm", newProg("-f -i -I -r -R -v -d -P -x --force --recursive --verbose --dir --one-file-system --preserve-root -W", "").
		withOptVal("--interactive").withLoose())
	allow("mkdir", newProg("-p -v --parents --verbose", "-m --mode").withLoose())
	allow("touch", newProg("-a -c -m -f -h --no-create --no-dereference", "-d -r -t --date --reference --time").withLoose())
	allow("chmod", chmodProg())
	allow("ln", newProg("-s -f -n -v -i -T -r -L -P -h -F --symbolic --force --no-dereference --verbose --interactive --no-target-directory --relative --logical --physical",
		"-t --target-directory").withLoose())
	allow("cp", newProg("-a -f -i -n -p -R -r -v -u -L -P -H -T -l -s -c --archive --force --interactive --no-clobber --recursive --verbose --update "+
		"--dereference --no-dereference --link --symbolic-link --no-target-directory --parents --attributes-only", "-t --target-directory").
		withOptVal("--preserve --reflink").withLoose())
	allow("mv", newProg("-f -i -n -v -u -T --force --interactive --no-clobber --verbose --update --no-target-directory", "-t --target-directory").withLoose())
	allow("tee", newProg("-a -i -p --append --ignore-interrupts", "").withOptVal("--output-error").withLoose())

	// Programs with an output file, a compress program, a temporary
	// directory or an operand that is written.
	allow("sort", newProg("-b -c -C -d -f -g -h -i -M -m -n -r -R -s -u -V -z --check --ignore-leading-blanks --dictionary-order --ignore-case "+
		"--general-numeric-sort --human-numeric-sort --ignore-nonprinting --month-sort --merge --numeric-sort --random-sort --reverse --stable "+
		"--unique --version-sort --zero-terminated --debug", "-k -t -S --key --field-separator --buffer-size --parallel --files0-from"))
	allow("uniq", newProg("-c -d -D -i -u -z --count --repeated --ignore-case --unique --zero-terminated", "-f -s -w --skip-fields --skip-chars --check-chars").
		withMaxOps(1)) // the second operand is the output file
	allow("tree", newProg("-a -d -f -i -l -p -s -u -g -h -D -F -q -N -Q -r -t -v -x -C -n -A -S -U --dirsfirst --noreport --prune --du --inodes --device",
		"-L -P -I --charset --filelimit --sort --timefmt --matchdirs"))
	allow("diff", newProg("-a -b -B -d -E -i -N -p -q -r -s -t -T -u -w -y -Z --brief --ignore-case --recursive --report-identical-files --normal "+
		"--side-by-side --ignore-all-space --ignore-space-change --ignore-blank-lines --new-file --text --minimal --expand-tabs --initial-tab "+
		"--strip-trailing-cr --show-c-function --left-column --suppress-common-lines --ignore-tab-expansion --no-dereference",
		"-U -C -I -x -F -W -L --width --context --ignore-matching-lines --exclude --from-file --to-file --label --show-function-line --tabsize").
		withOptVal("--unified --color").withLoose())
	allow("xxd", newProg("-a -b -E -e -i -p -r -u -ps -postscript -plain -C", "-c -g -l -o -s -n -N").withMaxOps(1))
	allow("base64", newProg("-d -D --decode --ignore-garbage", "-w --wrap -b --break").withMaxOps(1))
	gz := func(name string) *prog {
		p := newProg("-c -d -f -k -l -n -N -q -t -v -r -h -V --stdout --to-stdout --decompress --uncompress --keep --list --test --quiet --verbose "+
			"--no-name --fast --best --recursive --help --version", "").withNum()
		// Without -c or a listing, a file is compressed or expanded in place:
		// a new file beside it and the old one removed.
		p.need = func(seen map[string]bool) string {
			for _, k := range []string{"-c", "--stdout", "--to-stdout", "-l", "--list", "-t", "--test", "-h", "--help", "-V", "--version"} {
				if seen[k] {
					return ""
				}
			}
			return name + " without -c, -l or -t replaces its operand in place"
		}
		return p
	}
	allow("gzip", gz("gzip"))
	allow("gunzip", gz("gunzip"))
	// Extraction is plain as it is for tar: the files it writes are the
	// archive's (under -d), and a later git command or cd into the directory
	// is judged by writesGitState and the unknown-directory rule.
	allow("unzip", newProg("-l -v -p -t -z -Z -c -q -qq -o -n -j -a -aa -b -C -f -u -K -L -M -V -X -T -1 -h -s -U", "-d -P").withLoose())
	// date -s and an operand that is a time set the clock.
	dt := newProg("-u -R -j --utc --universal --rfc-email --rfc-2822 --rfc-3339", "-d -f -r -v --date --file --reference").withOptVal("--iso-8601 -I")
	dt.ops = func(ops []Word) string {
		for _, o := range ops {
			if !strings.HasPrefix(optText(o), "+") {
				return "date with an operand that is not a +FORMAT sets the clock"
			}
		}
		return ""
	}
	allow("date", dt)
	allow("hostname", newProg("-f -s -i -I -d -a -A -y --fqdn --short --ip-address --all-ip-addresses --domain --alias --long --yp --nis", "").withMaxOps(0))
	allow("file", newProg("-b -i -I -L -s -z -Z -k -h -n -N -p -r -v -E --brief --mime --mime-type --mime-encoding --dereference --keep-going "+
		"--no-dereference --special-files --uncompress --version --help", "-f -F -m -P -e --files-from --separator --magic-file --exclude").withLoose())
	// gofmt -w writes the files it names: only the listing and diff forms.
	allow("gofmt", newProg("-d -e -l -s", "-r").withLoose())
	// tfsec --out writes a report file.
	allow("tfsec", newProg("--no-colour --no-color --verbose --debug --soft-fail --include-passed --include-ignored --concise-output "+
		"--exclude-downloaded-modules --ignore-hcl-errors --run-statistics --no-module-downloads --force-all-dirs --version -h --help",
		"--format -f --minimum-severity --exclude -e --tfvars-file --workspace --exclude-path -x"))
	shapes["gsutil"] = func(args []Word, _ Invocation) string {
		// Global options -o and -i name boto settings and a service account
		// to impersonate; only the read subcommands are plain.
		for _, w := range args {
			if t := optText(w); strings.HasPrefix(t, "-o") || strings.HasPrefix(t, "-i") || strings.HasPrefix(t, "-boto") {
				return "the gsutil option " + t
			}
		}
		return valuedSubcommands(nil, "ls", "cat", "stat", "du", "hash", "version", "help")(args, Invocation{})
	}
	shapes["find"] = func(args []Word, inv Invocation) string { return findShape(args, inv) }
	// cd takes one directory: zsh's two-operand form, CDPATH-sensitive plain
	// names are the analysis's, and "-" is the previous directory, which the
	// analysis does not know.
	cd := newProg("-P -L", "").withMaxOps(1).withLoose()
	cd.ops = func(ops []Word) string {
		for _, o := range ops {
			if optText(o) == "-" {
				return "cd - goes to the previous directory"
			}
		}
		return ""
	}
	allow("cd", cd)

	for n := range inert {
		shapes[n] = nil
	}
	// Programs handled by their own shape elsewhere.
	for _, n := range []string{"applygate", "env"} {
		shapes[n] = nil
	}
}

// chmodProg: a mode such as -x or -w looks like an option, so words made of
// mode letters are operands.
func chmodProg() *prog {
	p := newProg("-R -f -v -c -h -H -L -P --recursive --silent --quiet --verbose --changes --no-dereference", "--reference").withLoose()
	p.opWord = modeWordRE.MatchString
	return p
}

var modeWordRE = regexp.MustCompile(`^-[rwxXstugoa]+$`)

// findShape accepts the find expressions that only test and print. A starting
// point that cannot be resolved may be an expression, and a word that is not
// a listed primary (-exec, -execdir, -ok, -okdir, -delete, -fprint, -fprint0,
// -fprintf, -fls and any other) is not plain.
func findShape(args []Word, inv Invocation) string {
	none := toSet("-print", "-print0", "-prune", "-depth", "-d", "-empty", "-true", "-false", "-xdev", "-mount", "-readable", "-writable",
		"-executable", "-nouser", "-nogroup", "-quit", "-daystart", "-ignore_readdir_race", "-noignore_readdir_race", "-noleaf", "-ls",
		"-a", "-o", "-and", "-or", "-not", "!", "(", ")", "-follow", "-nowarn", "-warn")
	one := toSet("-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-type", "-xtype", "-size", "-mtime",
		"-atime", "-ctime", "-mmin", "-amin", "-cmin", "-newer", "-anewer", "-cnewer", "-perm", "-user", "-group", "-uid", "-gid", "-links",
		"-inum", "-samefile", "-lname", "-ilname", "-maxdepth", "-mindepth", "-fstype", "-regextype", "-printf")
	newerXY := regexp.MustCompile(`^-newer[acBmt][acBmt]$`)
	i := 0
	// Global options and starting points come first.
	for i < len(args) {
		t := optText(args[i])
		switch t {
		case "-H", "-L", "-P", "-E", "-X", "-x", "-s":
			i++
			continue
		}
		if !args[i].Resolved && (t == "" || strings.HasPrefix(t, "-") || strings.HasPrefix(t, "(") || t == "!") {
			return "a find word that cannot be resolved may be an expression"
		}
		if strings.HasPrefix(t, "-") || t == "(" || t == "!" {
			break
		}
		i++
	}
	for ; i < len(args); i++ {
		w := args[i]
		t := optText(w)
		if !w.Resolved && (t == "" || strings.HasPrefix(t, "-")) {
			return "a find word that cannot be resolved may be an expression"
		}
		switch {
		case none[t]:
		case (t == "-exec" || t == "-execdir" || t == "-ok" || t == "-okdir") && inv.Followed:
			// The analysis took the command apart and judges it as an
			// invocation of its own; skip to its terminator.
			for i+1 < len(args) && optText(args[i+1]) != ";" && optText(args[i+1]) != "+" {
				i++
			}
			i++
		case one[t], newerXY.MatchString(t):
			if i+1 >= len(args) {
				return "the find primary " + t + " without its value"
			}
			i++
		default:
			return "the find expression " + t
		}
	}
	return ""
}
