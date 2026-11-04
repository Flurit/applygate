package classify

import (
	"os"
	"strings"

	"github.com/Flurit/applygate/internal/shell"
)

// UnknownGuardChange reports a command that changes something through a
// path the analysis cannot resolve (a loop variable, xargs, find -exec, an
// expansion inside a name) while the same command text names a place that
// holds a guard file. rm $f over ~/.claude/*, ls ~/.claude | xargs rm and
// cp x ~/.claude/set${X:-t}ings.json all end up here. "" when there is none.
func UnknownGuardChange(res *shell.Result, cmd, cwd string, opt Options) string {
	if opt.Guard == nil {
		return ""
	}
	changer := ""
	for _, inv := range res.Invocations {
		if len(inv.Args) == 0 || !inv.Args[0].Resolved {
			continue
		}
		name := shell.ProgName(inv.Args[0].Text)
		if !(writers[name] || removers[name] || copiers[name] || name == "tar" || name == "unzip" || name == "find" || name == "git" || name == "rsync") {
			continue
		}
		unknown := false
		for _, w := range inv.Args[1:] {
			if !w.Resolved && !strings.HasPrefix(w.Text, "-") {
				// A part of a path that cannot be resolved: also a prefix
				// in or beside a guard path.
				if w.Prefix != "" && w.Prefix != w.Text {
					if p := absPath(inv.Dir, w.Prefix+"*", opt.Home); opt.Guard.GlobTouches(p) {
						return name + " changes " + w.Prefix + "…, which may be a guard file"
					}
				}
				unknown = true
			}
		}
		for _, v := range inv.Via {
			if strings.Contains(v, "xargs") || strings.Contains(v, "find -exec") || strings.Contains(v, "parallel") {
				unknown = true
			}
		}
		if unknown {
			changer = name
		}
	}
	if changer == "" {
		return ""
	}
	home := opt.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	norm := strings.NewReplacer(";", " ", "|", " ", "&", " ", "(", " ", ")", " ", "`", " ", "\"", " ", "'", " ", "\n", " ", "<", " ", ">", " ", "{}", "")
	for _, tok := range strings.Fields(norm.Replace(cmd)) {
		if strings.HasPrefix(tok, "-") && !strings.Contains(tok, "=") {
			continue
		}
		if _, v, ok := strings.Cut(tok, "="); ok && strings.HasPrefix(tok, "-") {
			tok = v
		}
		tok = strings.Replace(strings.Replace(tok, "${HOME}", "~", 1), "$HOME", "~", 1)
		if !strings.Contains(tok, "/") && !strings.HasPrefix(tok, "~") || strings.Contains(tok, "$") {
			continue
		}
		p := absPath(cwd, tok, home)
		if strings.ContainsAny(tok, "*?[") {
			if opt.Guard.GlobTouches(p) {
				return changer + " changes paths it gets at run time, and this command names " + tok + ", which holds guard files"
			}
		} else if opt.Guard.Touches(p) {
			return changer + " changes paths it gets at run time, and this command names " + tok + ", which holds guard files"
		}
	}
	return ""
}
