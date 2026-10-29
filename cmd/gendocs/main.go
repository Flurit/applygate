// Command gendocs writes the generated documentation files. Today that is
// docs/hosts.md, rendered from the host capability table in internal/hook.
// Run through go generate: go generate ./internal/hook
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Flurit/applygate/internal/hook"
)

func main() {
	out := flag.String("out", "docs/hosts.md", "file to write")
	flag.Parse()
	if err := os.WriteFile(*out, []byte(hook.HostsMarkdown()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote", *out)
}
