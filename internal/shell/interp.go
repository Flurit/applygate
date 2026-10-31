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
// code loading, no network or cloud SDK, no decoded or assembled text, no
// function passed around by reference, and every file it writes, renames,
// links or removes named by a literal (or a name bound once to one and never
// rebound) that resolves to an ordinary configuration file under the working
// directory. A write whose target it cannot resolve keeps the body opaque (it
// fails closed). Such a body can only read and write ordinary files, so the
// mention is text, not a command, and the body is reported as a note instead
// of a problem. Anything the check does not understand keeps today's
// behaviour (a problem, so an ask or a block), including every language other
// than Python and Node.
//
// Python bodies are first split into code and literals (scan): the checks for
// names that run things look at the code alone, so a comment that says
// "remove" or an HCL string with "kube-system" in it does not trip them,
// while the checks for state, guard and credential files look at the whole
// text. Node bodies are checked as whole text (regular-expression literals
// make a Node scanner ambiguous), which is more conservative.

// pyImports allows the modules a file-editing script needs. Everything else,
// including local modules in the working directory, keeps the body opaque.
// pathlib is left out because Path objects are joined with the / operator,
// whose operands the target check cannot follow; fileinput because
// inplace=True rewrites whatever file list it is given; tempfile because its
// files land outside the working directory.
var pyImports = map[string]bool{
	"re": true, "sys": true, "os": true, "json": true, "glob": true, "fnmatch": true,
	"io": true, "string": true, "textwrap": true, "difflib": true, "itertools": true, "functools": true,
	"collections": true, "typing": true, "dataclasses": true, "datetime": true, "time": true, "math": true,
	"copy": true, "hashlib": true, "argparse": true, "yaml": true, "hcl2": true,
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

// pyDunderOK lists the double-underscore names an ordinary script uses; every
// other one reaches into the interpreter.
var pyDunderOK = map[string]bool{
	"__name__": true, "__main__": true, "__file__": true, "__doc__": true, "__future__": true,
	"__version__": true, "__all__": true, "__init__": true, "__str__": true, "__repr__": true,
	"__eq__": true, "__hash__": true, "__len__": true, "__iter__": true, "__enter__": true,
	"__exit__": true, "__post_init__": true, "__slots__": true, "__annotations__": true,
}

// A boundary before or after a path: the start or end of the text, a path
// separator, white space or a quote.
const pathEdge = `[/\s'"` + "`" + `]`

var (
	// pyFromRe and pyImportRe find import statements anywhere in the code
	// (after a colon or a semicolon as well as at the start of a line).
	pyFromRe   = regexp.MustCompile(`\bfrom\s+(\S+)\s+import\b([^\n;]*)`)
	pyImportRe = regexp.MustCompile(`(?:^|[^\w.])import\s+([^\n;]+)`)
	// pyDeny lists names that start processes, load code, decode text, reach
	// the environment or reach into the interpreter without an import
	// statement, wherever they appear in the text. Modules that need an
	// import are handled by the allowlist.
	pyDeny = regexp.MustCompile(`\b(\w*subprocess\w*|importlib|ctypes|pty|shutil|pickle|marshal|base64|codecs|boto3|botocore|builtins|__builtins__|__class__|__subclasses__|__dict__|__globals__|__code__|__loader__|__spec__|__reduce__|__getattribute__|__getattr__|__mro__|__bases__|__import__|environ|putenv|unsetenv|attrgetter|methodcaller|unsafe_load|full_load|Loader|add_constructor|add_multi_constructor|yaml\.(?:unsafe_|full_)?load\w*|sys\.modules)\b|\.os\b`)
	// pyBuiltinRef catches the builtins that evaluate or inspect code,
	// called or passed by reference (re.compile is fine; compile is not).
	pyBuiltinRef = regexp.MustCompile(`(?:^|[^.\w])(eval|exec|compile|getattr|setattr|delattr|globals|locals|vars|breakpoint|help|__import__)\b`)
	// pyExecName catches process starts, directory changes, indirect calls
	// and frame access through any receiver, called or passed by reference,
	// so an aliased module or a function handed to map() does not hide them.
	pyExecName = regexp.MustCompile(`\b(\w*(?:exec|spawn|popen|system|fork|subprocess)\w*|startfile|rmtree|dlopen|kill\w*|load_module|run_path|run_module|\w*chdir\w*|chroot|fdopen|FileType|__call__|call_tracing|call|settrace|setprofile|Formatter|get_field|format_map|vformat|interact|runsource|runcode|tb_frame|f_builtins|f_globals|f_locals|f_code|f_back|gi_frame|cr_frame|ag_frame)\b`)
	// pyDunder and pyPrivate catch the remaining interpreter internals.
	pyDunder  = regexp.MustCompile(`__\w+__`)
	pyPrivate = regexp.MustCompile(`\._[A-Za-z]\w*`)
	// pyViaModule catches os, io and sys reached through another module's
	// namespace (yaml.io.open, glob.os.rename), which the call scan anchors
	// would not recognise.
	pyViaModule = regexp.MustCompile(`\.(?:io|sys|posix|nt|builtins)\b`)
	// pyWriteRef matches the names of writing file functions; one that is
	// not followed by a call is passed by reference.
	pyWriteRef = regexp.MustCompile(`\b(open|FileIO|unlink|remove|rmdir|removedirs|mkdir|makedirs|chmod|chown|lchown|lchmod|truncate|mknod|mkfifo|utime|rename|renames|replace|link|symlink|copyfile|copy2|copytree|move|copymode|copystat)\b`)

	nodeRequireRe = regexp.MustCompile(`\b(?:require|import)\s*\(\s*(?:(['"` + "`" + `])([^'"` + "`" + `\n]*)['"` + "`" + `]|([^)]*))\)`)
	nodeImportRe  = regexp.MustCompile(`(?m)(?:^|;)[ \t]*import\s+(?:[^;'"\n]*?\s+from\s+)?['"]([^'"\n]+)['"]`)
	// nodeDeny lists what reaches a process, code loading, the environment
	// or the network without a require or import statement, plus the
	// decoders; modules that need a require or import are handled by the
	// allowlist.
	nodeDeny = regexp.MustCompile(`\b(child_process|constructor|Function|eval|globalThis|global|Reflect|Proxy|binding|dlopen|_load|mainModule|_linkedBinding|runInThisContext|runInNewContext|runInContext|compileFunction|fetch|XMLHttpRequest|WebSocket|WebAssembly|base64|atob|btoa|fromCharCode|unescape|decodeURI\w*|chdir)\b|process\s*\[|process\.env\s*(?:\.\w+|\[[^\]]*\])\s*=[^=]`)
	// nodeExecRef catches process starts and indirect calls, called or
	// referenced.
	nodeExecRef = regexp.MustCompile(`(?:^|[^.\w])(exec\w*|spawn\w*|fork|kill)\b|\.(execSync|execFileSync|execFile|spawn\w*|fork|kill|reverse|call|apply|bind)\b`)
	// nodeIndex matches a member reached with a string ( fs['writeFileSync'] );
	// group 1 is what precedes the bracket, so an array literal after a
	// keyword (for (p of ['a.tf'])) can be told apart.
	nodeIndex = regexp.MustCompile(`([\w$]+|[)\]])\s*\[\s*['"` + "`" + `]`)
	// nodeDestructure matches the destructuring import idiom, which names
	// functions without calling them; group 1 is the name list.
	nodeDestructure = regexp.MustCompile(`(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:require\s*\([^)]*\)|await\s+import\s*\([^)]*\))|import\s*\{([^}]*)\}\s*from\s*['"][^'"\n]*['"]`)
	nodeWriteRef    = regexp.MustCompile(`\b(writeFileSync|writeFile|appendFileSync|appendFile|unlinkSync|unlink|rmSync|rm|rmdirSync|rmdir|truncateSync|truncate|mkdirSync|mkdir|chmodSync|chmod|chownSync|chown|utimesSync|utimes|createWriteStream|openSync|open|renameSync|rename|copyFileSync|copyFile|symlinkSync|symlink|linkSync|link|cpSync|cp)\b`)

	// obfuscated matches text that assembles or decodes names at run time:
	// escaped characters, chr/fromhex, reversed slices, character maps.
	obfuscated = regexp.MustCompile(`\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\N\{|\\[0-7]{3}|\bchr\s*\(|\bfromhex\s*\(|\[::-1\]|\bmaketrans\s*\(|\.translate\s*\(`)

	// guardText matches guard, credential and applygate files wherever they
	// appear in a body (a body that names them is not a plain file edit).
	// The directory names need a path boundary, so provider.aws and
	// module.aws in HCL text are not credential files and applygate matches
	// only as a path segment or the config file.
	guardText = regexp.MustCompile(`(?i)\.applygate\.ya?ml|\.seatbelt\.ya?ml|(?:^|` + pathEdge + `)(?:applygate|seatbelt)/|\.claude/settings[\w.]*|managed-settings[\w.]*|\.codex/(?:hooks\.json|config\.toml)|\.cursor/hooks\.json|\.gemini/settings\.json|\.github/hooks/|\.github/copilot/settings[\w.]*|\.copilot/(?:hooks/|settings\.json)|\.windsurf/hooks\.json|\.codeium/(?:windsurf/)?hooks\.json|\.devin/(?:config|hooks\.v1)\.json|devin/config\.json|opencode/plugins/|\.clinerules/hooks/|\.cline/hooks/|Cline/Hooks/|(?:^|` + pathEdge + `|~)\.aws/(?:credentials|config)\b|~/\.aws\b|\.terraform\.d/credentials\.tfrc\.json|\.terraformrc\b|decisions\.jsonl|(?:^|` + pathEdge + `)\.(?:claude|codex|cursor|aws|terraform\.d)(?:$|` + pathEdge + `)|\.git/hooks`)
	// stateTarget matches state, lock and provider cache files: editing
	// those is state surgery, not a file edit.
	stateTarget = regexp.MustCompile(`\.tfstate|\.terraform/|\.terraform\.lock\.hcl`)
	// riskyText matches shell and tool start-up files, credential stores and
	// scheduler files wherever they appear in a body. Writes are governed by
	// the positive rule in writeTarget; this is the text-level backstop.
	riskyText = regexp.MustCompile(`(?:^|` + pathEdge + `)(?:\.(?:ssh|bashrc|bash_profile|bash_login|profile|zshrc|zshenv|zprofile|gitconfig|npmrc|netrc|pypirc|envrc|docker|kube)|authorized_keys|crontab|cron\.d|sitecustomize|usercustomize)(?:$|` + pathEdge + `)|\.pth(?:$|` + pathEdge + `)`)
	// configExt lists what a repository configuration file ends in; a write
	// to anything else keeps the body opaque.
	configExt = regexp.MustCompile(`\.(?:tf|tfvars|hcl|json|ya?ml|md|txt|toml|tftpl|tpl|csv|rst)$`)
)

// toolManifests are configuration files that a package or task manager runs:
// writing one is not a repository configuration edit.
var toolManifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "pyproject.toml": true, "pipfile": true,
	"cargo.toml": true, "composer.json": true, "taskfile.yml": true, "taskfile.yaml": true,
	"docker-compose.yml": true, "docker-compose.yaml": true, "compose.yml": true, "compose.yaml": true,
	"buildspec.yml": true, "buildspec.yaml": true, "appspec.yml": true, "appspec.yaml": true,
	"bitbucket-pipelines.yml": true, "azure-pipelines.yml": true, "azure-pipelines.yaml": true,
	"cloudbuild.yaml": true, "cloudbuild.yml": true, "atlantis.yaml": true, "atlantis.yml": true,
	"vercel.json": true, "netlify.toml": true, "fly.toml": true, "skaffold.yaml": true,
}

// fileCalls describes the file-access calls of a language: the names, how
// the call is anchored (python: bare or os./io.-prefixed, so str.replace is
// not os.replace; node: any receiver), which calls write and how many
// leading path arguments they take, which are open-like (writing when the
// mode argument says so or is unknown), and which make or remove
// directories (whose targets need no file extension).
type fileCalls struct {
	call  *regexp.Regexp // group 1: the function name
	write map[string]int // name -> number of leading path arguments that must resolve
	read  map[string]bool
	open  map[string]bool
	dir   map[string]bool
}

var pyFiles = fileCalls{
	call: regexp.MustCompile(`(?:^|[^.\w])(?:os\.|io\.|os\.path\.)?(open|FileIO|unlink|remove|rmdir|removedirs|mkdir|makedirs|chmod|chown|lchown|lchmod|truncate|mknod|mkfifo|utime|rename|renames|replace|link|symlink|copyfile|copy2|copytree|move|copymode|copystat|exists|isfile|isdir|listdir|scandir|glob|iglob|stat|lstat|access|getsize|walk)\s*\(`),
	write: map[string]int{
		"unlink": 1, "remove": 1, "rmdir": 1, "removedirs": 1, "mkdir": 1, "makedirs": 1, "chmod": 1, "chown": 1,
		"lchown": 1, "lchmod": 1, "truncate": 1, "mknod": 1, "mkfifo": 1, "utime": 1,
		"rename": 2, "renames": 2, "replace": 2, "link": 2, "symlink": 2, "copyfile": 2, "copy2": 2,
		"copytree": 2, "move": 2, "copymode": 2, "copystat": 2,
	},
	read: map[string]bool{"exists": true, "isfile": true, "isdir": true, "listdir": true, "scandir": true, "glob": true,
		"iglob": true, "stat": true, "lstat": true, "access": true, "getsize": true, "walk": true},
	open: map[string]bool{"open": true, "FileIO": true},
	dir:  map[string]bool{"mkdir": true, "makedirs": true, "rmdir": true, "removedirs": true},
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
	dir:  map[string]bool{"mkdirSync": true, "mkdir": true, "rmdirSync": true, "rmdir": true},
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
	// form with the joins collapsed, as the mention scan does. The whole
	// text, strings included, is scanned for state, guard, credential and
	// start-up files: a body that names one anywhere is not a plain edit,
	// whatever it does with the name.
	joined := dejoinLiterals(code)
	if loc := guardText.FindStringIndex(joined); loc != nil {
		return "names " + pathToken(joined, loc), false
	}
	lower := strings.ToLower(joined)
	for _, g := range guards {
		for _, needle := range guardNeedles(g) {
			if strings.Contains(lower, strings.ToLower(needle)) {
				return "names the guard file " + needle, false
			}
		}
	}
	if loc := stateTarget.FindStringIndex(joined); loc != nil {
		return "names the state file " + pathToken(joined, loc), false
	}
	if loc := riskyText.FindStringIndex(joined); loc != nil {
		return "names " + pathToken(joined, loc), false
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
		// Everything that runs or loads code is looked for in the code
		// alone, with string literals and comments removed.
		sc, err := scanPython(joined)
		if err != "" {
			return err, false
		}
		if name := pyBuiltinUse(sc); name != "" {
			return "uses " + name + "()", false
		}
		if m := pyExecName.FindStringSubmatch(sc); m != nil {
			return "uses " + m[1] + "()", false
		}
		for _, m := range pyDunder.FindAllString(sc, -1) {
			if !pyDunderOK[m] {
				return "uses " + m, false
			}
		}
		if m := pyPrivate.FindString(sc); m != "" {
			return "uses the private attribute " + m, false
		}
		if m := pyViaModule.FindString(sc); m != "" {
			return "reaches a module through another module (" + m + ")", false
		}
		if why, ok := pyImportsOK(sc); !ok {
			return why, false
		}
		if name := byReference(sc, pyWriteRef); name != "" {
			return "passes " + name + " by reference", false
		}
		files = pyFiles
	case "node":
		if m := nodeDeny.FindString(joined); m != "" {
			return "uses " + strings.TrimSpace(m), false
		}
		if m := nodeExecRef.FindStringSubmatch(joined); m != nil {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			return "uses " + name + "()", false
		}
		if nodeIndexed(joined) {
			return "reaches a member with a string index", false
		}
		for _, m := range nodeRequireRe.FindAllStringSubmatch(joined, -1) {
			if m[2] == "" {
				return "requires a module whose name is computed", false
			}
			if !nodeImports[strings.TrimPrefix(m[2], "node:")] {
				return "requires " + m[2], false
			}
		}
		for _, m := range nodeImportRe.FindAllStringSubmatch(joined, -1) {
			if !nodeImports[strings.TrimPrefix(m[1], "node:")] {
				return "imports " + m[1], false
			}
		}
		// Destructuring imports name functions without calling them; they
		// are fine unless a name is given an alias, which the call scan
		// would not recognise.
		rest := nodeDestructure.ReplaceAllStringFunc(joined, func(s string) string {
			if names := s[strings.Index(s, "{"):strings.Index(s, "}")]; strings.Contains(names, ":") || strings.Contains(names, " as ") {
				return s
			}
			return " "
		})
		if name := byReference(rest, nodeWriteRef); name != "" {
			return "passes " + name + " by reference", false
		}
		files = nodeFiles
	}
	targets, why := fileTargets(code, files)
	if why != "" {
		return why, false
	}
	for _, t := range targets {
		if t.write {
			if why := writeTarget(t.path, dir, t.dir); why != "" {
				return why, false
			}
		}
		full := path.Clean(t.path)
		if dir != "" && !path.IsAbs(full) {
			full = path.Join(dir, full)
		}
		if a.opt.ProtectedPath != nil && a.opt.ProtectedPath(full) {
			return "touches the guard file " + t.path, false
		}
	}
	return "only reads and writes files: no process start, code loading, network or AWS SDK use, and no state or guard file", true
}

// writeTarget applies the positive rule to one resolved write target: it
// must resolve under dir (no escape through ..), have no hidden segment
// (.github/, .git/, .envrc, guard directories), not be a tool manifest, and,
// unless dirOp (mkdir and friends), end in a repository-configuration
// extension. The empty string means the target passes. With dir unknown a
// relative target that stays below the directory is judged on its own text
// and anything else fails.
func writeTarget(t, dir string, dirOp bool) string {
	clean := path.Clean(t)
	rel := clean
	switch {
	case dir != "":
		d := path.Clean(dir)
		full := clean
		if !path.IsAbs(clean) {
			full = path.Join(d, clean)
		}
		if full == d || !strings.HasPrefix(full, d+"/") {
			return "writes " + t + " outside the working directory"
		}
		rel = full[len(d)+1:]
	case path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../"):
		return "writes " + t + " outside the working directory"
	}
	for _, seg := range strings.Split(rel, "/") {
		if strings.HasPrefix(seg, ".") {
			return "writes the hidden file " + t
		}
	}
	base := strings.ToLower(path.Base(rel))
	if toolManifests[base] {
		return "writes the tool manifest " + t
	}
	if !dirOp && !configExt.MatchString(base) {
		return "writes " + t + " (not a repository configuration file)"
	}
	return ""
}

// jsKeywords are the words an array literal may follow directly.
var jsKeywords = map[string]bool{"of": true, "in": true, "return": true, "typeof": true, "case": true, "yield": true,
	"await": true, "delete": true, "void": true, "throw": true, "new": true, "else": true, "do": true, "instanceof": true}

// nodeIndexed reports whether the code reaches a member with a string
// index, which would hide a function name from the call scan.
func nodeIndexed(code string) bool {
	for _, m := range nodeIndex.FindAllStringSubmatch(code, -1) {
		if !jsKeywords[m[1]] {
			return true
		}
	}
	return false
}

// pathToken widens a match to the path it sits in: the surrounding text up
// to white space, a quote or an operator.
func pathToken(s string, loc []int) string {
	start, end := loc[0], loc[1]
	sep := func(c byte) bool { return strings.IndexByte(" \t\r\n'\"`,;=<>|", c) >= 0 }
	// A match may begin or end on the boundary it required.
	for start < end && sep(s[start]) {
		start++
	}
	for end > start && sep(s[end-1]) {
		end--
	}
	for start > 0 && !sep(s[start-1]) {
		start--
	}
	for end < len(s) && !sep(s[end]) {
		end++
	}
	return s[start:end]
}

// pyBuiltinUse returns the first code-inspecting builtin the code uses,
// called or passed by reference. A script that assigns the name first
// (vars = json.load(...)) has shadowed the builtin, and that name is then
// its own.
func pyBuiltinUse(code string) string {
	shadowed := map[string]bool{}
	for _, m := range pyBuiltinRef.FindAllStringSubmatchIndex(code, -1) {
		name := code[m[2]:m[3]]
		if shadowed[name] {
			continue
		}
		rest := strings.TrimLeft(code[m[3]:], " \t")
		if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
			shadowed[name] = true
			continue
		}
		return name
	}
	return ""
}

// byReference returns the first function name in names that is used without
// being called (not followed by an opening parenthesis or a member access):
// such a name is being passed around, and the call scan would not see the
// eventual call.
func byReference(code string, names *regexp.Regexp) string {
	for _, m := range names.FindAllStringSubmatchIndex(code, -1) {
		rest := strings.TrimLeft(code[m[1]:], " \t")
		if rest == "" || (rest[0] != '(' && rest[0] != '.') {
			return code[m[2]:m[3]]
		}
	}
	return ""
}

// scanPython returns the code of a Python body with every string literal
// emptied and every comment removed, so that a scan for names sees code
// only. Prefixed strings, triple quotes and escapes follow the Python lexer;
// the expressions inside f-string braces are code and are kept. A string
// that is not closed on its line (which Python rejects too) is an error, so
// a body the scanner cannot read stays opaque.
func scanPython(code string) (string, string) {
	var b strings.Builder
	if _, err := pyCode(code, 0, false, &b); err != "" {
		return "", err
	}
	return b.String(), ""
}

// pyCode copies code until the end of s or, when nested, until the brace
// that closes an f-string expression; it returns the index after that.
func pyCode(s string, i int, nested bool, b *strings.Builder) (int, string) {
	depth := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		case c == '\'' || c == '"':
			j, err := pyString(s, i, b)
			if err != "" {
				return 0, err
			}
			i = j
			continue
		case nested && c == '}' && depth == 0:
			return i + 1, ""
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		}
		b.WriteByte(c)
		i++
	}
	if nested {
		return 0, "an f-string expression is not closed"
	}
	return i, ""
}

// pyString skips the string literal that opens at s[i], writing an empty
// literal (and the code of any f-string expressions) to b.
func pyString(s string, i int, b *strings.Builder) (int, string) {
	q := s[i]
	// The prefix letters just before the quote say whether this is an
	// f-string (whose braces hold code).
	j := i
	for j > 0 && i-j < 2 && strings.IndexByte("rRbBuUfF", s[j-1]) >= 0 {
		j--
	}
	fstr := (j == 0 || !isWordByte(s[j-1])) && strings.ContainsAny(s[j:i], "fF")
	triple := i+2 < len(s) && s[i+1] == q && s[i+2] == q
	b.WriteByte(q)
	b.WriteByte(q)
	if triple {
		i += 3
	} else {
		i++
	}
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\':
			i += 2
			continue
		case c == q && (!triple || i+2 < len(s) && s[i+1] == q && s[i+2] == q):
			if triple {
				return i + 3, ""
			}
			return i + 1, ""
		case c == '\n' && !triple:
			return 0, "a string literal is not closed"
		case fstr && c == '{':
			if i+1 < len(s) && s[i+1] == '{' {
				i += 2
				continue
			}
			b.WriteByte('{')
			j, err := pyCode(s, i+1, true, b)
			if err != "" {
				return 0, err
			}
			b.WriteByte('}')
			i = j
			continue
		}
		i++
	}
	return 0, "a string literal is not closed"
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// pyImportsOK checks every import statement in the code against the
// allowlist, including ones after a colon (if 1: import asyncio).
func pyImportsOK(code string) (string, bool) {
	for _, m := range pyFromRe.FindAllStringSubmatch(code, -1) {
		if why, ok := pyImportOK("from", m[1]+" import "+m[2]); !ok {
			return why, false
		}
	}
	rest := pyFromRe.ReplaceAllString(code, " ")
	for _, m := range pyImportRe.FindAllStringSubmatch(rest, -1) {
		if why, ok := pyImportOK("import", m[1]); !ok {
			return why, false
		}
	}
	return "", true
}

// pyImportOK checks one import statement against the allowlist.
func pyImportOK(kind, rest string) (string, bool) {
	rest = strings.TrimSpace(rest)
	if kind == "from" {
		mod, names, _ := strings.Cut(rest, " import ")
		mod = strings.TrimSpace(mod)
		if mod == "os" {
			// from os import system (or *) would bypass the attribute check.
			return "imports names from os", false
		}
		top, _, _ := strings.Cut(mod, ".")
		if top == "" || !pyImports[top] {
			return "imports " + mod, false
		}
		for _, n := range strings.FieldsFunc(names, func(r rune) bool { return r == ',' || r == '(' || r == ')' || r == ' ' }) {
			if pyWriteRef.MatchString(n) && pyWriteRef.FindString(n) == n {
				// from io import FileIO would hide the call behind a new name.
				return "imports " + n + " from " + mod, false
			}
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

// rebinders match the places a name is bound other than by an assignment:
// loop variables, with/except/import aliases, def and class names, lambda
// and function parameters, catch clauses, match-case captures, arrow-function
// parameters, ES module imports, global and nonlocal declarations and walrus
// targets. Group 1 holds the names.
var rebinders = []*regexp.Regexp{
	regexp.MustCompile(`\bfor\s*\(?\s*(?:(?:const|let|var)\s+)?([^\n;]*?)\s+(?:in|of)\s`),
	regexp.MustCompile(`\bas\s+([A-Za-z_$][\w$]*)`),
	regexp.MustCompile(`\blambda\b([^:\n]*):`),
	regexp.MustCompile(`\b(?:def|class)\s+(\w+)`),
	regexp.MustCompile(`\bdef\s+\w+\s*(?:\[[^\]]*\])?\s*\(([^)]*)\)`),
	regexp.MustCompile(`\bcase\b([^:\n]*):`),
	regexp.MustCompile(`\bimport\s+([^;\n]*?)\s+from\b`),
	regexp.MustCompile(`\bfunction\b[^(\n]*\(([^)]*)\)`),
	regexp.MustCompile(`\bcatch\s*\(([^)]*)\)`),
	regexp.MustCompile(`\(([^()\n]*)\)\s*=>`),
	regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*=>`),
	regexp.MustCompile(`\b(?:global|nonlocal)\s+([^\n;]+)`),
	regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*:=`),
}

var identRe = regexp.MustCompile(`[A-Za-z_$][\w$]*`)

// assignments maps names bound exactly once, to a complete string literal,
// and never bound anywhere else, to that literal. A name assigned anything
// else, assigned more than once, or bound by a loop, a with/except/import
// alias, a parameter, a destructuring pattern or a declaration is absent,
// so a later use of it does not resolve.
func assignments(code string) map[string]string {
	vars := map[string]string{}
	unresolved := map[string]bool{}
	poison := func(names string) {
		for _, id := range identRe.FindAllString(names, -1) {
			unresolved[id] = true
			delete(vars, id)
		}
	}
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
			// Comparisons (==, !=, <=, >=) and arrows (=>) bind nothing.
			if strings.HasPrefix(rhs, "=") || strings.HasPrefix(rhs, ">") || name == "" || strings.ContainsRune("!<>", rune(name[len(name)-1])) {
				continue
			}
			op := ""
			if n := len(name); strings.ContainsRune("+-*/%|&^", rune(name[n-1])) {
				op, name = string(name[n-1]), strings.TrimSpace(name[:n-1])
			}
			if !isIdent(name) {
				// A destructuring pattern, subscript, attribute or
				// annotation binds every name in it to something the check
				// cannot follow; a call with keyword arguments binds nothing.
				if !strings.Contains(name, "(") || strings.HasPrefix(name, "(") {
					poison(name)
				}
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
	for _, re := range rebinders {
		for _, m := range re.FindAllStringSubmatch(code, -1) {
			poison(m[1])
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

// target is one path a file-access call names.
type target struct {
	path  string
	write bool // the call creates, changes, renames, links or removes it
	dir   bool // the call makes or removes a directory
}

// fileTargets lists the paths the body's file-access calls name. Every path
// argument of a writing call must be a complete literal or a name bound to
// one; otherwise why says what could not be resolved. Unresolved arguments
// of read-only calls are ignored.
func fileTargets(code string, files fileCalls) (targets []target, why string) {
	vars := assignments(code)
	seen := map[string]bool{}
	add := func(t string, write, dir bool) {
		key := t
		if write {
			key = "w:" + t
		}
		if t != "" && !seen[key] {
			seen[key] = true
			targets = append(targets, target{t, write, dir})
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
			mode, ok := resolve(1)
			write := len(args) > 1 && (!ok || strings.ContainsAny(mode, "wax+"))
			if t, ok := resolve(0); ok {
				add(t, write, false)
			} else if write {
				return nil, name + "() writes to a path it builds at run time"
			}
		case n > 0:
			for i := 0; i < n; i++ {
				t, ok := resolve(i)
				if !ok {
					return nil, name + "() writes to a path it builds at run time"
				}
				add(t, true, files.dir[name])
			}
		case files.read[name]:
			if t, ok := resolve(0); ok {
				add(t, false, false)
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
