package shell

import (
	"path"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// File-only interpreter bodies.
//
// Code given to python -c, node -e, a here-document or a script file is opaque
// to the shell analyzer; its only signal is a textual mention of an
// infrastructure tool, an AWS SDK or a guard file. Coding agents edit .tf and
// .hcl files with small Python scripts whose text mentions terraform (a regex
// over ${terraform.workspace}, an HCL block being inserted), which used to be
// reported as dynamic and asked for in protected and standard tiers.
//
// fileOnly recognises a body that cannot run anything: no process start, no
// code loading, no network or cloud SDK, no decoded or assembled text, and
// every file it writes, renames, links or removes named by a literal that is
// not a state, credential, guard or system file. A write whose target it
// cannot resolve keeps the body opaque (it fails closed). Such a body can
// only read and write ordinary files, so the mention is text, not a command,
// and the body is reported as a note instead of a problem. Anything the check
// does not understand keeps today's behaviour (a problem, so an ask or a
// block), including every language other than Python and Node.

// pyImports allows the modules a file-editing script needs. Everything else,
// including local modules in the working directory, keeps the body opaque.
// pathlib is left out because Path objects are joined with the / operator,
// whose operands the target check cannot follow; fileinput because
// inplace=True rewrites whatever file list it is given.
var pyImports = map[string]bool{
	"re": true, "sys": true, "os": true, "json": true, "glob": true, "fnmatch": true,
	"io": true, "string": true, "textwrap": true, "difflib": true, "itertools": true, "functools": true,
	"collections": true, "typing": true, "dataclasses": true, "datetime": true, "time": true, "math": true,
	"copy": true, "hashlib": true, "tempfile": true, "argparse": true, "yaml": true, "hcl2": true,
	"tomllib": true, "tomli": true, "toml": true, "configparser": true, "csv": true, "uuid": true,
	"random": true, "enum": true, "abc": true, "contextlib": true, "operator": true, "pprint": true,
	"warnings": true, "shlex": true, "unicodedata": true, "errno": true, "stat": true, "filecmp": true,
	"ast": true, "traceback": true, "struct": true, "decimal": true, "fractions": true,
	"bisect": true, "heapq": true, "array": true, "__future__": true,
}

// nodeImports allows the built-in modules a file-editing script needs, with
// or without the node: prefix.
var nodeImports = map[string]bool{
	"fs": true, "fs/promises": true, "path": true, "os": true, "util": true, "assert": true,
	"buffer": true, "string_decoder": true, "url": true, "events": true, "stream": true,
	"readline": true, "crypto": true, "querystring": true,
}

var (
	// pyImportRe finds import statements, including ones after a semicolon.
	pyImportRe = regexp.MustCompile(`(?m)(?:^|;)[ \t]*(import|from)[ \t]+([^\n#;]+)`)
	// pyDeny lists names that start processes, load code, decode text, reach
	// the environment or reach into the interpreter without an import
	// statement, wherever they appear. Modules that need an import are
	// handled by the allowlist.
	pyDeny = regexp.MustCompile(`\b(subprocess|importlib|ctypes|pty|shutil|pickle|marshal|base64|codecs|boto3|botocore|builtins|__builtins__|__class__|__subclasses__|__dict__|__globals__|__code__|__loader__|__spec__|__reduce__|__getattribute__|__getattr__|__mro__|__bases__|__import__|environ|putenv|unsetenv|attrgetter|methodcaller|unsafe_load|full_load|Loader|add_constructor|add_multi_constructor|yaml\.load\w*|sys\.modules)\b|\.os\b`)
	// pyBuiltinCall catches the builtins that evaluate or inspect code when
	// called bare (re.compile is fine; compile is not).
	pyBuiltinCall = regexp.MustCompile(`(?:^|[^.\w])(eval|exec|compile|getattr|globals|locals|vars|breakpoint|help)\s*\(`)
	// pyExecCall catches process starts and directory changes through any
	// receiver, so an aliased module does not hide them.
	pyExecCall = regexp.MustCompile(`\b(\w*(?:exec|spawn|popen|system|fork)\w*|startfile|rmtree|dlopen|kill|killpg|load_module|run_path|run_module|chdir|chroot)\s*\(`)

	nodeRequireRe = regexp.MustCompile(`\b(?:require|import)\s*\(\s*(?:(['"` + "`" + `])([^'"` + "`" + `\n]*)['"` + "`" + `]|([^)]*))\)`)
	nodeImportRe  = regexp.MustCompile(`(?m)(?:^|;)[ \t]*import\s+(?:[^;'"\n]*?\s+from\s+)?['"]([^'"\n]+)['"]`)
	// nodeDeny lists what reaches a process, code loading, the environment
	// or the network without a require or import statement, plus the
	// decoders; modules that need a require or import are handled by the
	// allowlist.
	nodeDeny     = regexp.MustCompile(`\b(child_process|constructor|Function|eval|globalThis|global|Reflect|Proxy|binding|dlopen|_load|mainModule|_linkedBinding|runInThisContext|runInNewContext|runInContext|compileFunction|fetch|XMLHttpRequest|WebSocket|WebAssembly|base64|atob|btoa|fromCharCode|unescape|decodeURI\w*|chdir)\b|process\s*\[|process\.env\s*(?:\.\w+|\[[^\]]*\])\s*=[^=]`)
	nodeExecCall = regexp.MustCompile(`(?:^|[^.\w])(exec\w*|spawn\w*|fork|kill)\s*\(|\.(execSync|execFileSync|execFile|spawn\w*|fork|kill|reverse)\s*\(`)

	// obfuscated matches text that assembles or decodes names at run time:
	// escaped characters, chr/fromhex, reversed slices, character maps.
	obfuscated = regexp.MustCompile(`\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\N\{|\\[0-7]{3}|\bchr\s*\(|\bfromhex\s*\(|\[::-1\]|\bmaketrans\s*\(|\.translate\s*\(`)

	// guardText matches guard, credential and seatbelt files wherever they
	// appear in a body (a body that names them is not a plain file edit).
	guardText = regexp.MustCompile(`(?i)\.seatbelt\.ya?ml|\.claude/settings[\w.]*|managed-settings[\w.]*|\.codex/(?:hooks\.json|config\.toml)|\.cursor/hooks\.json|\.aws/credentials|\.aws/config|\.terraform\.d/credentials\.tfrc\.json|\.terraformrc|decisions\.jsonl|seatbelt|\.claude\b|\.codex\b|\.cursor\b|\.aws\b|\.terraform\.d\b|\.git/hooks`)
	// stateTarget matches write targets that are state, lock or provider
	// cache files: editing those is state surgery, not a file edit.
	stateTarget = regexp.MustCompile(`\.tfstate|\.terraform/|\.terraform\.lock\.hcl`)
	// riskyTarget matches write targets outside a repository's own
	// configuration: system paths, shell and tool start-up files, git
	// internals, and program files a later command could run.
	riskyTarget = regexp.MustCompile(`^/(?:proc|dev|sys|etc|usr|bin|sbin|lib|lib64|boot|var|opt|root)(?:/|$)|(?:^|/)\.(?:ssh|bashrc|bash_profile|bash_login|profile|zshrc|zshenv|zprofile|gitconfig|npmrc|pip|docker|config)(?:/|$)|(?:^|/)\.git(?:/|$)|crontab|authorized_keys|\.pth$|sitecustomize|usercustomize|\.py$|\.sh$|\.bash$|\.zsh$|\.js$|\.mjs$|\.cjs$|Makefile$`)
)

// fileCalls describes the file-access calls of a language: the names, how
// the call is anchored (python: bare or os./io.-prefixed, so str.replace is
// not os.replace; node: any receiver), which calls write and how many
// leading path arguments they take, and which are open-like (writing when
// the mode argument says so or is unknown).
type fileCalls struct {
	call  *regexp.Regexp // group 1: the function name
	write map[string]int // name -> number of leading path arguments that must resolve
	read  map[string]bool
	open  map[string]bool
}

var pyFiles = fileCalls{
	call: regexp.MustCompile(`(?:^|[^.\w])(?:os\.|io\.|os\.path\.)?(open|unlink|remove|rmdir|removedirs|mkdir|makedirs|chmod|chown|lchmod|truncate|mknod|mkfifo|utime|rename|renames|replace|link|symlink|copyfile|copy2|copytree|move|copymode|copystat|exists|isfile|isdir|listdir|scandir|glob|iglob|stat|lstat|access|getsize|walk)\s*\(`),
	write: map[string]int{
		"unlink": 1, "remove": 1, "rmdir": 1, "removedirs": 1, "mkdir": 1, "makedirs": 1, "chmod": 1, "chown": 1,
		"lchmod": 1, "truncate": 1, "mknod": 1, "mkfifo": 1, "utime": 1,
		"rename": 2, "renames": 2, "replace": 2, "link": 2, "symlink": 2, "copyfile": 2, "copy2": 2,
		"copytree": 2, "move": 2, "copymode": 2, "copystat": 2,
	},
	read: map[string]bool{"exists": true, "isfile": true, "isdir": true, "listdir": true, "scandir": true, "glob": true,
		"iglob": true, "stat": true, "lstat": true, "access": true, "getsize": true, "walk": true},
	open: map[string]bool{"open": true},
}

var nodeFiles = fileCalls{
	call: regexp.MustCompile(`\b(writeFileSync|writeFile|appendFileSync|appendFile|unlinkSync|unlink|rmSync|rm|rmdirSync|rmdir|truncateSync|truncate|mkdirSync|mkdir|chmodSync|chmod|chownSync|chown|utimesSync|utimes|createWriteStream|openSync|open|renameSync|rename|copyFileSync|copyFile|symlinkSync|symlink|linkSync|link|cpSync|cp|readFileSync|readFile|readdirSync|readdir|statSync|stat|lstatSync|lstat|existsSync|accessSync|access|createReadStream|realpathSync|realpath)\s*\(`),
	write: map[string]int{
		"writeFileSync": 1, "writeFile": 1, "appendFileSync": 1, "appendFile": 1, "unlinkSync": 1, "unlink": 1,
		"rmSync": 1, "rm": 1, "rmdirSync": 1, "rmdir": 1, "truncateSync": 1, "truncate": 1, "mkdirSync": 1, "mkdir": 1,
		"chmodSync": 1, "chmod": 1, "chownSync": 1, "chown": 1, "utimesSync": 1, "utimes": 1, "createWriteStream": 1,
		"renameSync": 2, "rename": 2, "copyFileSync": 2, "copyFile": 2, "symlinkSync": 2, "symlink": 2,
		"linkSync": 2, "link": 2, "cpSync": 2, "cp": 2,
	},
	read: map[string]bool{"readFileSync": true, "readFile": true, "readdirSync": true, "readdir": true, "statSync": true,
		"stat": true, "lstatSync": true, "lstat": true, "existsSync": true, "accessSync": true, "access": true,
		"createReadStream": true, "realpathSync": true, "realpath": true},
	open: map[string]bool{"openSync": true, "open": true},
}

// literalRe matches one complete string literal with an optional Python
// prefix; f-strings and template literals with substitutions are not
// literals.
var literalRe = regexp.MustCompile(`^([rRbBuUfF]{0,2})(['"` + "`" + `])([^'"` + "`" + `\n]*)['"` + "`" + `]$`)

// fileOnly reports whether code for interpreter bn can only read and write
// ordinary files. args are the interpreter's other arguments (flags and the
// script's own arguments reach the body as input, so a guard file there
// counts), dir the directory the body runs in. On success why describes what
// was checked; on failure why names the first construct that keeps the body
// opaque, or is empty when the language is not understood at all.
func (a *analyzer) fileOnly(bn, code string, args []Word, dir string) (why string, ok bool) {
	guards := a.opt.ProtectedPaths
	var lang string
	switch {
	case strings.HasPrefix(bn, "python"):
		lang = "python"
	case bn == "node":
		lang = "node"
	default:
		// Only Python and Node bodies are understood; the rest keep the
		// plain "cannot be analyzed" reason.
		return "", false
	}
	// Python folds identifiers to NFKC, so a full-width name is the ASCII one.
	code = norm.NFKC.String(code)
	for _, w := range args {
		if !w.Resolved {
			return "an argument cannot be resolved", false
		}
		if guardText.MatchString(w.Text) || stateTarget.MatchString(w.Text) {
			return "an argument names a state, credential or guard file", false
		}
	}
	for _, m := range Mentions(code) {
		if strings.Contains(m, "boto") || strings.Contains(m, "aws-sdk") {
			return "uses an AWS SDK", false
		}
	}
	// Names split across string literals ('sub'+'process') are tested in a
	// form with the joins collapsed, as the mention scan does.
	joined := dejoinLiterals(code)
	if loc := guardText.FindString(joined); loc != "" {
		return "names " + strings.ToLower(loc), false
	}
	lower := strings.ToLower(joined)
	for _, g := range guards {
		for _, needle := range guardNeedles(g) {
			if strings.Contains(lower, strings.ToLower(needle)) {
				return "names the guard file " + needle, false
			}
		}
	}
	if m := obfuscated.FindString(code); m != "" {
		return "builds text at run time (" + strings.TrimSpace(m) + ")", false
	}
	var files fileCalls
	switch lang {
	case "python":
		if m := pyDeny.FindString(joined); m != "" {
			return "uses " + strings.TrimSpace(m), false
		}
		if m := pyBuiltinCall.FindStringSubmatch(code); m != nil {
			return "uses " + m[1] + "()", false
		}
		if m := pyExecCall.FindStringSubmatch(code); m != nil {
			return "uses " + m[1] + "()", false
		}
		for _, m := range pyImportRe.FindAllStringSubmatch(code, -1) {
			if why, ok := pyImportOK(m[1], m[2]); !ok {
				return why, false
			}
		}
		files = pyFiles
	case "node":
		if m := nodeDeny.FindString(joined); m != "" {
			return "uses " + strings.TrimSpace(m), false
		}
		if m := nodeExecCall.FindStringSubmatch(code); m != nil {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			return "uses " + name + "()", false
		}
		for _, m := range nodeRequireRe.FindAllStringSubmatch(code, -1) {
			if m[2] == "" {
				return "requires a module whose name is computed", false
			}
			if !nodeImports[strings.TrimPrefix(m[2], "node:")] {
				return "requires " + m[2], false
			}
		}
		for _, m := range nodeImportRe.FindAllStringSubmatch(code, -1) {
			if !nodeImports[strings.TrimPrefix(m[1], "node:")] {
				return "imports " + m[1], false
			}
		}
		files = nodeFiles
	}
	targets, why := fileTargets(code, files)
	if why != "" {
		return why, false
	}
	// The target text is scanned as written; the directory it resolves
	// against is checked only with the config's guard patterns, so a
	// repository that itself lives under a .claude or seatbelt directory is
	// not mistaken for a guard file.
	for _, t := range targets {
		clean := path.Clean(t)
		switch {
		case stateTarget.MatchString(clean):
			return "touches the state file " + t, false
		case guardText.MatchString(clean):
			return "touches the guard file " + t, false
		case riskyTarget.MatchString(clean):
			return "touches " + t + " (not a repository configuration file)", false
		}
		full := clean
		if dir != "" && !path.IsAbs(clean) {
			full = path.Join(dir, clean)
		}
		if a.opt.ProtectedPath != nil && a.opt.ProtectedPath(full) {
			return "touches the guard file " + t, false
		}
	}
	return "only reads and writes files: no process start, code loading, network or AWS SDK use, and no state or guard file", true
}

// pyImportOK checks one import statement against the allowlist.
func pyImportOK(kind, rest string) (string, bool) {
	rest = strings.TrimSpace(rest)
	if kind == "from" {
		mod, _, _ := strings.Cut(rest, " ")
		mod = strings.TrimSpace(mod)
		if mod == "os" {
			// from os import system (or *) would bypass the attribute check.
			return "imports names from os", false
		}
		top, _, _ := strings.Cut(mod, ".")
		if top == "" || !pyImports[top] {
			return "imports " + mod, false
		}
		return "", true
	}
	for _, m := range strings.Split(rest, ",") {
		m = strings.TrimSpace(m)
		if i := strings.Index(m, " as "); i >= 0 {
			if strings.TrimSpace(m[:i]) == "os" {
				// import os as o would hide o.rename and friends.
				return "imports os under another name", false
			}
			m = strings.TrimSpace(m[:i])
		}
		top, _, _ := strings.Cut(m, ".")
		if top == "" || !pyImports[top] {
			return "imports " + m, false
		}
	}
	return "", true
}

// assignments maps names bound exactly once, to a complete string literal,
// to that literal. A name assigned anything else, or more than once, is
// absent, so a later use of it does not resolve.
func assignments(code string) map[string]string {
	vars := map[string]string{}
	unresolved := map[string]bool{}
	for _, line := range strings.Split(code, "\n") {
		for _, stmt := range strings.Split(line, ";") {
			s := strings.TrimSpace(stmt)
			for _, kw := range []string{"const ", "let ", "var "} {
				s = strings.TrimPrefix(s, kw)
			}
			name, rhs, found := strings.Cut(s, "=")
			if !found {
				continue
			}
			name = strings.TrimSpace(name)
			op := ""
			if n := len(name); n > 0 && strings.ContainsRune("+-*/%|&^", rune(name[n-1])) {
				op, name = string(name[n-1]), strings.TrimSpace(name[:n-1])
			}
			if !isIdent(name) || strings.HasPrefix(rhs, "=") {
				continue
			}
			rhs = strings.TrimSuffix(strings.TrimSpace(rhs), ";")
			lit, ok := literal(strings.TrimSpace(rhs))
			if _, dup := vars[name]; op != "" || !ok || unresolved[name] || dup {
				unresolved[name] = true
				delete(vars, name)
				continue
			}
			vars[name] = lit
		}
	}
	return vars
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || r == '$' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// literal returns the value of a complete string literal. f-strings and
// template literals with substitutions do not count.
func literal(s string) (string, bool) {
	m := literalRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	if strings.ContainsAny(m[1], "fF") || m[2] == "`" && strings.Contains(m[3], "${") {
		return "", false
	}
	return m[3], true
}

// fileTargets lists the paths the body's file-access calls name. Every path
// argument of a writing call must be a complete literal or a name bound to
// one; otherwise why says what could not be resolved. Unresolved arguments
// of read-only calls are ignored.
func fileTargets(code string, files fileCalls) (targets []string, why string) {
	vars := assignments(code)
	seen := map[string]bool{}
	add := func(t string) {
		if t != "" && !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	for _, m := range files.call.FindAllStringSubmatchIndex(code, -1) {
		name := code[m[2]:m[3]]
		args := callArgs(code[m[1]:])
		resolve := func(i int) (string, bool) {
			if i >= len(args) {
				return "", false
			}
			a := strings.TrimSpace(args[i])
			if v, ok := literal(a); ok {
				return v, true
			}
			if v, ok := vars[a]; ok && isIdent(a) {
				return v, true
			}
			return "", false
		}
		n := files.write[name]
		switch {
		case files.open[name]:
			n = 0
			mode, ok := resolve(1)
			if len(args) > 1 && (!ok || strings.ContainsAny(mode, "wax+")) {
				n = 1
			}
			if t, ok := resolve(0); ok {
				add(t)
			} else if n == 1 {
				return nil, name + "() writes to a path it builds at run time"
			}
		case n > 0:
			for i := 0; i < n; i++ {
				t, ok := resolve(i)
				if !ok {
					return nil, name + "() writes to a path it builds at run time"
				}
				add(t)
			}
		case files.read[name]:
			if t, ok := resolve(0); ok {
				add(t)
			}
		}
	}
	return targets, ""
}

// callArgs splits the argument list that starts right after an opening
// parenthesis at top-level commas, honouring nested brackets and string
// quotes. It stops at the matching parenthesis or after 4 KB.
func callArgs(s string) []string {
	var args []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s) && i < 4096; i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return append(args, s[start:i])
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
	}
	return append(args, s[start:min(len(s), 4096)])
}

// guardNeedles turns a protected-path pattern into the literal texts a body
// would have to contain to name that file: the pattern without its leading
// **/ and trailing /** when no glob characters remain, and its last plain
// segment.
func guardNeedles(pattern string) []string {
	p := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(pattern), "**/"), "/**")
	if p == "" {
		return nil
	}
	var out []string
	if !strings.ContainsAny(p, "*?[") {
		out = append(out, p)
	}
	if b := path.Base(p); b != "." && b != "/" && b != p && !strings.ContainsAny(b, "*?[") {
		out = append(out, b)
	}
	return out
}
