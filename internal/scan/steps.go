package scan

import (
	"fmt"
	"io"
	"strings"
)

// Step is one thing a person does to move up a boundary level: the level it
// belongs to, a title, the credentials or files it is about, and the lines
// that say what to do. The command builds them from the boundary checks
// (cmd/applygate/boundary_steps.go); doctor --boundary and scan --boundary
// print them the same way.
type Step struct {
	Level    int
	Title    string
	Subjects []string
	Lines    []string
}

// Steps is what follows the level in a boundary report.
type Steps struct {
	Header string
	Items  []Step
	// Note is one line after the items, such as which steps can be done first.
	Note string
}

// StepsClose ends every block of steps. It says who runs them and what the
// report does not show, so a list of steps is never read as a promise.
const StepsClose = "A person runs these; an agent should not. applygate checks the credentials on this machine only, from a sample " +
	"(docs/limits.md), and does not show that production is out of reach. The setup advice follows docs/credentials.md, " +
	"which is not yet checked against each provider's documentation (docs/limits.md)."

// maxSubjects bounds how many credentials a step names before "and N more".
const maxSubjects = 5

// Render writes the steps, each line prefixed by indent. home is shortened
// to ~ in the text.
func (s *Steps) Render(w io.Writer, indent, home string) {
	if s == nil || s.Header == "" {
		return
	}
	fmt.Fprintf(w, "%s%s\n", indent, s.Header)
	for _, it := range s.Items {
		label := "   "
		if it.Level > 0 {
			label = fmt.Sprintf("L%d ", it.Level)
		}
		title := it.Title
		if n := len(it.Subjects); n > 0 {
			shown := it.Subjects
			more := ""
			if n > maxSubjects {
				shown, more = it.Subjects[:maxSubjects], fmt.Sprintf(" and %d more", n-maxSubjects)
			}
			title += ": " + strings.Join(shown, ", ") + more
		}
		fmt.Fprintf(w, "%s  %s %s\n", indent, label, homeAsTilde(title, home))
		for _, l := range it.Lines {
			fmt.Fprintf(w, "%s       %s\n", indent, homeAsTilde(l, home))
		}
	}
	if len(s.Items) == 0 {
		return
	}
	if s.Note != "" {
		fmt.Fprintf(w, "%s  %s\n", indent, s.Note)
	}
	for _, l := range wrap(StepsClose, 100) {
		fmt.Fprintf(w, "%s  %s\n", indent, l)
	}
}

// wrap breaks text into lines of at most width characters, at spaces.
func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
