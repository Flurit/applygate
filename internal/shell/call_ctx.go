package shell

// callCtx is what call0 knows about a command once it has resolved the
// program: the words, the program's name and its base name, and the state the
// branches that handle one program need.
type callCtx struct {
	args, rest []Word
	name, bn   string
	redirs     []Redir
	cmdSt, st  *state
	via        []string
	depth      int
	in         stdin
	record     func()
}
