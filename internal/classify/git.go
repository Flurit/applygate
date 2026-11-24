package classify

import (
	"strings"

	"github.com/Flurit/applygate/internal/shell"
)

// gitSubcommand returns a git call's subcommand, the words after it, and
// the directory it runs in (after -C).
func gitSubcommand(args []shell.Word, dir, home string) (string, []shell.Word, string) {
	base := dir
	i := 0
	for i < len(args) {
		t := args[i].Text
		switch {
		case t == "-C" && i+1 < len(args):
			base = absPath(base, args[i+1].Text, home)
			i += 2
			continue
		case t == "-c" && i+1 < len(args):
			i += 2
			continue
		case strings.HasPrefix(t, "-"):
			i++
			continue
		}
		break
	}
	if i >= len(args) {
		return "", nil, base
	}
	return args[i].Text, args[i+1:], base
}

// gitTargets returns the paths a git command replaces or removes in the
// working tree: mv and rm arguments, paths checked out or restored from
// another ref, and the whole tree for apply, am and stash pop or apply.
func gitTargets(args []shell.Word, dir, home string) []string {
	sub, rest, base := gitSubcommand(args, dir, home)
	if sub == "" {
		return nil
	}
	abs := func(p string) string { return absPath(base, p, home) }
	// The commands that rewrite the work tree rewrite all of it, not the
	// directory they run in: a state file anywhere in the repository.
	root := func() string { return repoRoot(abs(".")) }
	var out []string
	afterDashes := func() []string {
		var ps []string
		seen := false
		for _, w := range rest {
			if w.Text == "--" {
				seen = true
				continue
			}
			if seen && w.Resolved {
				ps = append(ps, abs(w.Text))
			}
		}
		return ps
	}
	switch sub {
	case "mv", "rm":
		for _, w := range rest {
			if w.Resolved && !strings.HasPrefix(w.Text, "-") {
				out = append(out, abs(w.Text))
			}
		}
	case "checkout", "reset":
		for _, w := range rest {
			// These replace the working tree with the committed one,
			// modified state files included.
			if sub == "reset" && (w.Text == "--hard" || w.Text == "--keep" || w.Text == "--merge") ||
				sub == "checkout" && (w.Text == "-f" || w.Text == "--force" || w.Text == "-B" || w.Text == "--discard-changes" || w.Text == "--merge") {
				out = append(out, root())
			}
		}
		if sub == "checkout" {
			// git checkout REV switches the work tree to REV; with -b NEW
			// only a start point does.
			pos, newBranch := 0, false
			for _, w := range rest {
				switch {
				case w.Text == "--":
				case w.Text == "-b" || w.Text == "-B":
					newBranch = true
				case !strings.HasPrefix(w.Text, "-"):
					pos++
				}
			}
			if pos > 0 && (!newBranch || pos > 1) {
				out = append(out, root())
			}
		}
		out = append(out, afterDashes()...)
		if sub == "checkout" {
			// "git checkout ref path": without --, an argument that is a
			// guard file or holds one is a path being restored.
			for _, w := range rest {
				if w.Resolved && !strings.HasPrefix(w.Text, "-") && w.Text != "--" {
					out = append(out, abs(w.Text))
				}
			}
		}
	case "restore":
		for _, w := range rest {
			if w.Resolved && !strings.HasPrefix(w.Text, "-") && w.Text != "--" {
				out = append(out, abs(w.Text))
			}
		}
	case "clean":
		// git clean removes untracked files from the directory it runs in
		// down, or under the pathspecs it is given. A pathspec with magic
		// (:/) or a pattern may reach the whole repository.
		paths := false
		for j := 0; j < len(rest); j++ {
			t := rest[j].Text
			switch {
			case t == "-e" || t == "--exclude":
				j++
			case t == "--" || strings.HasPrefix(t, "-"):
			case !rest[j].Resolved || strings.HasPrefix(t, ":") || strings.ContainsAny(t, "*?["):
				out, paths = append(out, root()), true
			default:
				out, paths = append(out, abs(t)), true
			}
		}
		if !paths {
			out = append(out, abs("."))
		}
	case "checkout-index", "read-tree", "merge", "pull", "rebase", "cherry-pick", "revert", "switch":
		out = append(out, root())
	case "apply", "am":
		out = append(out, root())
	case "stash":
		if len(rest) == 0 || rest[0].Text == "pop" || rest[0].Text == "apply" || rest[0].Text == "push" || rest[0].Text == "save" || strings.HasPrefix(rest[0].Text, "-") {
			out = append(out, root())
		}
	}
	return out
}

// gitMagic splits a git pathspec with magic (:(top,glob)path, :/path,
// :!path) into the path and whether it is from the repository root. Excluding
// magic (:!, :^, :(exclude)) names nothing.
func gitMagic(spec string) (path string, top bool) {
	rest := spec[1:]
	switch {
	case strings.HasPrefix(rest, "("):
		end := strings.Index(rest, ")")
		if end < 0 {
			return "", false
		}
		for _, m := range strings.Split(rest[1:end], ",") {
			switch m {
			case "top":
				top = true
			case "exclude":
				return "", false
			}
		}
		return rest[end+1:], top
	case strings.HasPrefix(rest, "/"):
		return rest[1:], true
	case strings.HasPrefix(rest, "!") || strings.HasPrefix(rest, "^"):
		return "", false
	}
	return rest, false
}

// gitTreeWrites returns the working tree a git command rewrites without
// naming paths: switching branches, merging, resetting, rebasing, pulling,
// cherry-picking and reverting.
func gitTreeWrites(args []shell.Word, dir, home string) []string {
	base := dir
	i := 0
	for i < len(args) {
		t := args[i].Text
		switch {
		case t == "-C" && i+1 < len(args):
			if !args[i+1].Resolved {
				return []string{writtenUnknown}
			}
			base = absPath(base, args[i+1].Text, home)
			i += 2
			continue
		case (t == "-c" || t == "--git-dir" || t == "--work-tree") && i+1 < len(args):
			i += 2
			continue
		case strings.HasPrefix(t, "-"):
			i++
			continue
		}
		break
	}
	if i >= len(args) || base == "" {
		return nil
	}
	switch args[i].Text {
	case "checkout", "switch", "merge", "reset", "rebase", "pull", "cherry-pick", "revert", "am", "apply", "stash", "restore", "worktree", "read-tree", "clean", "sparse-checkout", "update-index", "submodule":
		return []string{base}
	}
	return nil
}
