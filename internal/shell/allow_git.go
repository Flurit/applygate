package shell

import "strings"

// Stage 6a: git by subcommand, each with the options it may be given, by exact
// name. This replaces gitSubs (a subcommand list) and gitDeny (a list of the
// options that run a program), which lost to every option nobody listed.
//
// What the lists leave out, on purpose, for every subcommand:
//   - options that run a program: --ext-diff, --textconv, --filters, --exec,
//     rebase -x, --upload-pack, --receive-pack, grep -O/--open-files-in-pager,
//     --tool, signing (-S, --gpg-sign, --show-signature), --edit and the
//     interactive forms (an editor), --help (a pager), -c on clone;
//   - options that write a file by name: --output, -o, --lost-found,
//     format-patch without --stdout, archive -o;
//   - options that point at another repository or directory: --git-dir,
//     --work-tree, --template, --separate-git-dir, --exec-path;
//   - abbreviations of long options: git accepts any unique prefix, the list
//     names whole options only (a call that abbreviates asks).
// Where an option's value is its own word the list says so (vals); an option
// whose value is only given with "=", or is optional, is optVal and takes no
// following word, so a word after it is read as an option if it looks like one.

// gp builds a git prog; every flag and optional-value option also has its
// --no- negation, which is always harmless.
func gp(flags, vals, optVals string) *prog {
	p := newProg(flags, vals).withOptVal(optVals)
	var neg []string
	for f := range p.flags {
		if strings.HasPrefix(f, "--") && !strings.HasPrefix(f, "--no-") {
			neg = append(neg, f)
		}
	}
	for f := range p.optVal {
		if strings.HasPrefix(f, "--") && !strings.HasPrefix(f, "--no-") {
			neg = append(neg, f)
		}
	}
	p.derived = map[string]bool{}
	for _, f := range neg {
		p.flags["--no-"+f[2:]] = true
		p.derived["--no-"+f[2:]] = true
	}
	return p
}

// merge adds the options of other to p.
func (p *prog) merge(flags, vals, optVals string) *prog {
	q := gp(flags, vals, optVals)
	for k := range q.flags {
		p.flags[k] = true
	}
	for k := range q.vals {
		p.vals[k] = true
	}
	for k := range q.optVal {
		p.optVal[k] = true
	}
	return p
}

const (
	gitDiffFlags = "-p -u -U -s --patch --raw --patch-with-raw --patch-with-stat --numstat --shortstat --summary --name-only --name-status --check --minimal " +
		"--patience --histogram --ignore-space-at-eol -b --ignore-space-change -w --ignore-all-space --ignore-blank-lines --ignore-cr-at-eol -R -a --text " +
		"--full-index --binary -z -M -C -B -D -l --find-copies-harder --irreversible-delete --pickaxe-all --pickaxe-regex --function-context -W " +
		"--no-ext-diff --no-textconv --no-prefix --default-prefix --indent-heuristic --compact-summary --cumulative --exit-code --quiet " +
		"--ignore-all-space --no-renames --cc -c -m --first-parent --remerge-diff --ita-invisible-in-index --ita-visible-in-index"
	gitDiffVals = "-S -G -I -O"
	gitDiffOpt  = "--stat --dirstat --color --color-words --color-moved --color-moved-ws --word-diff --word-diff-regex --abbrev --relative --diff-algorithm " +
		"--anchored --ws-error-highlight --src-prefix --dst-prefix --line-prefix --inter-hunk-context --unified --diff-filter --find-renames --find-copies " +
		"--break-rewrites --submodule --ignore-submodules --output-indicator-new --output-indicator-old --output-indicator-context --rotate-to --skip-to " +
		"--dirstat-by-file --stat-width --stat-name-width --stat-count --stat-graph-width --find-object --diff-merges"

	gitRevFlags = "--all --first-parent --merges --reverse --topo-order --date-order --author-date-order --simplify-by-decoration --simplify-merges " +
		"--full-history --sparse --dense --boundary --left-right --cherry-pick --cherry-mark --cherry -g --walk-reflogs --follow --oneline --abbrev-commit " +
		"--source --graph --children --parents --left-only --right-only --count --do-walk --use-mailmap --mailmap --log-size --show-pulls --invert-grep " +
		"--all-match -i --regexp-ignore-case -E --extended-regexp --basic-regexp -F --fixed-strings -P --perl-regexp --relative-date --merge " +
		"--alternate-refs --single-worktree --stdin --not --no-merges --reflog --exclude-first-parent-only --bisect " +
		"--no-color"
	gitRevVals = "-n -L"
	gitRevOpt  = "--branches --tags --remotes --glob --exclude --min-parents --max-parents --decorate --decorate-refs --decorate-refs-exclude --abbrev " +
		"--notes --show-notes --encoding --format --pretty --date --author --committer --grep --since --until --after --before --max-count --skip " +
		"--since-as-filter --exclude-hidden --no-walk"
)

var gitBuiltinStrategy = toSet("ort", "recursive", "resolve", "octopus", "ours", "subtree")

// strategyOK: -s NAME runs git-merge-NAME from PATH for a name that is not
// built in.
func strategyOK(opt string, v Word) string {
	if opt == "-s" || opt == "--strategy" {
		if !v.Resolved || !gitBuiltinStrategy[v.Text] {
			return "a git merge strategy that is not built in"
		}
	}
	return ""
}

// gitProgs are the plain subcommands of git. A nil entry is a subcommand that
// is listed so that its own message is given (push).
var gitProgs = map[string]*prog{}

func gitSub(name string, p *prog) {
	gitProgs[name] = p
	if p != nil {
		allowCmds = append(allowCmds, cmdEntry{"git", []string{name}, p})
	}
}

func init() {
	// git --output (diff, log, show and others) writes the file it names; archive
	// and format-patch name theirs with -o.
	regOutputs("git", "--output")
	log := func() *prog {
		return gp(gitDiffFlags+" "+gitRevFlags, gitDiffVals+" "+gitRevVals, gitDiffOpt+" "+gitRevOpt).withNum().withLoose()
	}
	// Unresolved words are not loose for git: "$X" may be --output=file, and
	// the shapes before this table refused them too.
	strict := func(p *prog) *prog { p.loose = false; return p }

	fam := func(p *prog, f string) *prog { p.family = f; return p }
	gitSub("status", strict(gp("-s -b -v -u -z --short --branch --show-stash --long --verbose --null --ahead-behind --renames -uno -unormal -uall", "",
		"--porcelain --untracked-files --ignored --ignore-submodules --column --find-renames")))
	gitSub("log", fam(strict(log()), "rev"))
	gitSub("whatchanged", fam(strict(log()), "rev"))
	gitSub("show", fam(strict(log()), "rev"))
	gitSub("diff", strict(gp(gitDiffFlags+" --cached --staged --no-index --merge-base -1 -2 -3 --base --ours --theirs --stat", gitDiffVals, gitDiffOpt+" --ignore-submodules --submodule").withNum()))
	gitSub("range-diff", strict(gp(gitDiffFlags+" --left-only --right-only --no-dual-color", gitDiffVals, gitDiffOpt+" --creation-factor --notes")))
	gitSub("shortlog", fam(strict(log().merge("-n -s -e --numbered --summary --email -c --committer", "", "-w --format --group")), "rev"))
	gitSub("rev-list", fam(strict(log().merge("--objects --objects-edge --objects-edge-aggressive --header --timestamp --no-object-names --in-commit-order --use-bitmap-index -z",
		"", "--disk-usage --filter --pretty --missing")), "rev"))
	gitSub("blame", strict(gp("-b -l -t -s -e --show-email -f --show-name -n --show-number -p --porcelain --line-porcelain --incremental -w -M -C --root "+
		"--show-stats --score-debug --progress --reverse --color-lines --color-by-age --first-parent", "-L -S --contents --ignore-revs-file --ignore-rev",
		"--since --abbrev --date --encoding --minimal --diff-algorithm").withNum()))
	gitSub("describe", strict(gp("--all --tags --contains --long --exact-match --debug --always --first-parent", "",
		"--abbrev --candidates --match --exclude --dirty --broken")))
	gitSub("name-rev", strict(gp("--tags --all --annotate-stdin --name-only --undefined --always --stdin", "", "--refs --exclude")))
	gitSub("merge-base", strict(gp("-a --all --octopus --independent --is-ancestor --fork-point", "", "")))
	gitSub("for-each-ref", strict(gp("--shell -s --perl --python --tcl --ignore-case --stdin --include-root-refs", "",
		"--count --sort --format --points-at --merged --no-merged --contains --no-contains --color")))
	gitSub("show-ref", strict(gp("--head --heads --tags -d --dereference -s --verify --exists -q --quiet", "", "--hash --abbrev --exclude-existing")))
	// symbolic-ref reads with one operand; a second operand sets a reference.
	sr := strict(gp("-q --quiet --short --recurse", "", ""))
	sr.maxOps = 1
	gitSub("symbolic-ref", sr)
	gitSub("check-ignore", strict(gp("-q --quiet -v --verbose -n --non-matching --stdin -z --no-index", "", "")))
	gitSub("rev-parse", strict(gp("--show-toplevel --git-dir --is-inside-work-tree --verify -q --quiet --symbolic --symbolic-full-name --absolute-git-dir "+
		"--git-common-dir --show-prefix --show-cdup --show-superproject-working-tree --is-bare-repository --is-shallow-repository --all --revs-only "+
		"--no-revs --flags --no-flags --sq --local-env-vars --is-inside-git-dir --not --end-of-options --show-ref-format", "--default --prefix --git-path --resolve-git-dir",
		"--abbrev-ref --short --show-object-format --path-format --disambiguate --glob --exclude --branches --tags --remotes")))
	gitSub("ls-files", strict(gp("-c --cached -d --deleted -m --modified -o --others -i --ignored -s --stage -u --unmerged -k --killed -z -t -v -f "+
		"--exclude-standard --error-unmatch --full-name --debug --eol --deduplicate --recurse-submodules --sparse --directory --empty-directory --resolve-undo",
		"-x -X --exclude --exclude-from --exclude-per-directory", "--with-tree --abbrev --format")))
	gitSub("ls-tree", strict(gp("-d -r -t -l --long -z --name-only --name-status --object-only --full-name --full-tree", "", "--abbrev --format")))
	gitSub("cat-file", strict(gp("-t -s -e -p -Z --batch-all-objects --allow-unknown-type --buffer --follow-symlinks --unordered --mailmap --use-mailmap",
		"", "--batch --batch-check --batch-command --path")))
	gitSub("count-objects", strict(gp("-v --verbose -H --human-readable", "", "")))
	gitSub("fsck", strict(gp("--full --strict --unreachable --dangling --root --tags --cache --reflogs --name-objects --connectivity-only --progress --verbose", "", "")))
	gitSub("version", strict(gp("--build-options", "", "")))
	gitSub("help", strict(gp("-a --all -g --guides -c --config --verbose --no-aliases --no-external-commands", "", "")))
	// config: reading, and setting a key the key rules judge (gitConfigShape).
	// grep: -O and --open-files-in-pager run a program and are left out.
	gitSub("grep", strict(gp("-i -I -w -v -n -c -l -L -h -H --full-name -E -G -P -F -a -o -q -r -p -W --and --or --not --all-match --cached --index "+
		"--untracked --exclude-standard --recurse-submodules --null -z --heading --break --show-function --function-context --column --files-with-matches "+
		"--files-without-match --count --invert-match --word-regexp --ignore-case --fixed-strings --extended-regexp --basic-regexp --perl-regexp "+
		"--line-number --only-matching --quiet --text --recursive --name-only --no-recursive", "-e -f -A -B -C --max-depth --threads --context --after-context --before-context",
		"--color --max-count")).withNum())
	gitSub("config", strict(gp("-l --list --get --get-all --get-regexp --get-urlmatch --get-color --get-colorbool --global --system --local --worktree "+
		"--bool --int --bool-or-int --bool-or-str --path --expiry-date -z --null --name-only --show-origin --show-scope --includes --unset --unset-all "+
		"--add --replace-all --remove-section --fixed-value", "-f --file --blob -t --type --default --comment --value --url", "")))
	gitSub("notes", firstOp(strict(gp("", "--ref", "")), "notes", "", "list", "show"))
	gitSub("bundle", firstOp(strict(gp("-q --quiet", "", "")), "bundle", "verify", "list-heads"))

	// Changes to the work tree and the index.
	gitSub("add", strict(gp("-A --all -u --update -n --dry-run -v --verbose -f --force -N --intent-to-add --ignore-removal --refresh --ignore-errors "+
		"--ignore-missing --renormalize --sparse --pathspec-file-nul", "", "--chmod --pathspec-from-file")))
	gitSub("mv", strict(gp("-f --force -k -n --dry-run -v --verbose", "", "")))
	gitSub("rm", strict(gp("-f --force -n --dry-run -r -q --quiet --cached --ignore-unmatch --sparse --pathspec-file-nul", "", "--pathspec-from-file")))
	gitSub("restore", strict(gp("-S --staged -W --worktree --ours --theirs -m --merge --ignore-unmatch --overlay --progress -q --quiet --pathspec-file-nul",
		"-s --source", "--conflict --recurse-submodules --pathspec-from-file")))
	gitSub("reset", strict(gp("--soft --mixed --hard --merge --keep -q --quiet -N --intent-to-add --refresh --pathspec-file-nul", "",
		"--recurse-submodules --pathspec-from-file")))
	gitSub("clean", strict(gp("-f --force -n --dry-run -d -x -X -q --quiet", "-e", "--exclude")))
	commit := strict(gp("-a --all -q --quiet -v --verbose --amend -s --signoff --no-verify -n --allow-empty --allow-empty-message --no-post-rewrite "+
		"--reset-author --dry-run --short --branch --long -z --null --status --no-edit -u -uno -unormal -uall", "-m --message -F --file -C --reuse-message --trailer",
		"--author --date --porcelain --cleanup --untracked-files --pathspec-from-file"))
	// Without a message the commit opens the editor of the environment.
	commit.need = func(seen map[string]bool) string {
		for _, k := range []string{"-m", "--message", "-F", "--file", "-C", "--reuse-message", "--no-edit", "--dry-run", "--short", "--porcelain"} {
			if seen[k] {
				return ""
			}
		}
		return "git commit without a message opens an editor"
	}
	commit.with = []string{"-m", "x"}
	gitSub("commit", commit)
	gitSub("checkout", strict(gp("-q --quiet -f --force -m --merge --detach -d --guess -t --ours --theirs --ignore-other-worktrees --overwrite-ignore --progress "+
		"-l --pathspec-file-nul", "-b -B --orphan", "--track --conflict --recurse-submodules --pathspec-from-file")))
	gitSub("switch", strict(gp("-d --detach -f --force --discard-changes -m --merge --guess -t --ignore-other-worktrees -q --quiet --progress",
		"-c -C --create --force-create --orphan", "--track --recurse-submodules --conflict")))
	gitSub("branch", strict(gp("-a --all -r --remotes -l --list -v -vv -t --verbose --show-current --no-contains -i --ignore-case --no-abbrev -q --quiet -t --create-reflog",
		"", "--contains --merged --no-merged --points-at --format --sort --column --abbrev --track --color")))
	tag := strict(gp("-l --list -d --delete -a --annotate -f --force -i --ignore-case --create-reflog -n", "-m --message -F --file",
		"--contains --no-contains --merged --no-merged --points-at --sort --format --column --cleanup --color")).withNum()
	// An annotated tag without a message opens the editor of the environment.
	tag.need = func(seen map[string]bool) string {
		if (seen["-a"] || seen["--annotate"]) && !(seen["-m"] || seen["--message"] || seen["-F"] || seen["--file"]) {
			return "git tag -a without a message opens an editor"
		}
		return ""
	}
	tag.with = []string{"-m", "x"}
	gitSub("tag", tag)
	gitSub("stash", strict(gp("-u --include-untracked -a --all -k --keep-index -q --quiet --index --staged -p --patch --only-untracked -S --stat --name-only --name-status",
		"-m --message", "--pathspec-from-file")))
	gitSub("apply", strict(gp("--stat --numstat --summary --check --index --cached -3 --3way -R --reverse --reject -v --verbose -q --quiet -p -C "+
		"--ignore-space-change --ignore-whitespace --inaccurate-eof --allow-overlap --apply --binary --recount -z --intent-to-add", "",
		"--whitespace --directory --include --exclude")).withNum())
	gitSub("worktree", strict(gp("-f --force --detach --checkout --lock --guess-remote --track -q --quiet -n --dry-run -v --verbose --porcelain -z --orphan --relative-paths",
		"-b -B --reason --expire", "")))
	gitSub("sparse-checkout", firstOp(strict(gp("--cone --sparse-index --stdin --skip-checks", "", "")), "sparse-checkout", "list", "set", "add", "reinit", "disable", "init"))
	gitSub("archive", strict(gp("-v --verbose -l --list --worktree-attributes -0 -1 -2 -3 -4 -5 -6 -7 -8 -9", "", "--format --prefix")))
	gitSub("format-patch", func() *prog {
		p := strict(gp(gitDiffFlags+" --stdout -N --numbered --signoff -s --cover-letter --stat --no-signature --zero-commit --progress --root -k --keep-subject -1 -2 -3 -4 -5 -6 -7 -8 -9",
			gitDiffVals, gitDiffOpt+" --attach --inline --thread --in-reply-to --subject-prefix --start-number --reroll-count -v --suffix --signature --base --notes")).withNum()
		p.with = []string{"--stdout"}
		p.need = func(seen map[string]bool) string {
			if !seen["--stdout"] {
				return "git format-patch without --stdout writes patch files"
			}
			return ""
		}
		return p
	}())

	// History: these move or rewrite branches. -s is checked: a strategy that
	// is not built in is a program named by PATH.
	mergeFlags := "--no-ff --ff --ff-only --squash --commit --no-commit --no-edit --abort --continue --quit --autostash --stat -n --log --allow-unrelated-histories " +
		"--verify-signatures --no-verify --signoff -q --quiet -v --verbose --rerere-autoupdate --progress --overwrite-ignore --verify"
	gitSub("merge", strict(gp(mergeFlags, "-s --strategy -X --strategy-option -m --message -F --file", "--log")).withValOK(strategyOK))
	gitSub("pull", strict(gp(mergeFlags+" -r --rebase --all -a --prune -p --tags -t --force -f --dry-run --unshallow --update-head-ok -u --append --ipv4 --ipv6 -4 -6 --atomic",
		"-s --strategy -X --strategy-option --depth --deepen --jobs -j --shallow-since --shallow-exclude -o --server-option",
		"--rebase --recurse-submodules --filter --autostash --set-upstream")).withValOK(strategyOK))
	gitSub("rebase", strict(gp("--continue --abort --skip --quit --autosquash --autostash --keep-base --fork-point --root --force-rebase -f --rebase-merges -m --merge "+
		"--no-verify --verify --committer-date-is-author-date --reset-author-date --ignore-date --ignore-whitespace -q --quiet -v --verbose --stat "+
		"--update-refs --reapply-cherry-picks --apply --signoff --rerere-autoupdate --keep-empty --allow-empty-message -n --show-current-patch",
		"--onto -s --strategy -X --strategy-option", "--empty --whitespace")).withValOK(strategyOK))
	gitSub("cherry-pick", strict(gp("-x -n --no-commit -s --signoff --ff --allow-empty --allow-empty-message --keep-redundant-commits --continue --abort --skip --quit "+
		"--rerere-autoupdate --no-edit", "-m --mainline --strategy -X --strategy-option", "--empty")).withValOK(strategyOK))
	gitSub("revert", strict(gp("-n --no-commit -s --signoff --continue --abort --skip --quit --rerere-autoupdate --no-edit",
		"-m --mainline --strategy -X --strategy-option", "")).withValOK(strategyOK))
	gitSub("am", strict(gp("--continue --abort --skip --quit -3 --3way -q --quiet -s --signoff -k --keep-cr -u --reject --ignore-space-change --ignore-whitespace "+
		"--committer-date-is-author-date --ignore-date --no-verify -n --scissors --message-id -m --keep-non-patch -r --resolved --allow-empty", "",
		"--whitespace --directory --exclude --include --empty")).withNum())

	// Network: the repository named is checked by gitRemoteArg.
	netFlags := "-q --quiet -v --verbose --progress --ipv4 --ipv6 -4 -6"
	gitSub("fetch", strict(gp(netFlags+" --all -a --prune -p --tags -t --force -f --dry-run --unshallow --update-head-ok -u --append --refetch --atomic "+
		"--prune-tags --set-upstream --multiple -m --porcelain --stdin --write-fetch-head --auto-maintenance --auto-gc --show-forced-updates",
		"--depth --deepen --jobs -j --shallow-since --shallow-exclude -o --server-option", "--recurse-submodules --filter --negotiation-tip")))
	gitSub("ls-remote", strict(gp("-q --quiet -t --tags -h --heads --refs --get-url --symref --exit-code", "-o --server-option", "--sort")))
	gitSub("clone", strict(gp(netFlags+" --no-checkout -n --bare --mirror --single-branch --no-tags --sparse --local -l --no-hardlinks --dissociate --also-filter-submodules "+
		"--shallow-submodules --remote-submodules --reject-shallow", "--depth --branch -b --origin -o --jobs -j", "--recurse-submodules --filter --shallow-since --shallow-exclude")))
	// push is never plain (it moves the upstream branch the provider lock
	// check trusts); it is listed so that the message says so.
	gitSub("push", nil)
	gitSub("remote", strict(gp("-v --verbose -n --push --all", "", "")))
	gitSub("reflog", func() *prog {
		p := fam(strict(log().merge("-n", "", "")), "rev")
		p.ops = func(o []Word) string {
			for _, w := range o {
				if t := optText(w); t == "expire" || t == "delete" {
					return "git reflog " + t + " destroys reflog entries"
				}
			}
			return ""
		}
		return p
	}())
	gitSub("init", strict(gp("-q --quiet --bare", "-b --initial-branch", "--shared --object-format --ref-format")))
}
