package classify

import (
	"strings"

	"github.com/Flurit/applygate/internal/shell"
)

// httpMutation classifies network clients that send a request other than a
// read: a DELETE to a cloud or cluster API deletes what it names, and any
// other non-GET/HEAD request (an explicit method, a request body, a form or an
// upload) changes it, with whatever credentials the call or an earlier one
// obtained (an HCP Terraform run is a POST with a JSON body). Requests to this
// machine are ordinary work unless they are signed.
func httpMutation(base Action, name string, args []shell.Word) (Action, bool) {
	if name == "gh" || name == "glab" {
		// gh api -X DELETE, gh repo delete, gh secret delete and
		// gh workflow run (which starts a pipeline that can apply or
		// destroy) act on the remote repository and its automation.
		var pos []string
		method := ""
		body := false
		for i, w := range args {
			t := w.Text
			k, v, eq := strings.Cut(t, "=")
			switch {
			case (t == "-X" || t == "--method") && i+1 < len(args):
				method = strings.ToUpper(args[i+1].Text)
			case strings.HasPrefix(t, "-X") && len(t) > 2:
				method = strings.ToUpper(t[2:])
			case k == "--method" && eq:
				method = strings.ToUpper(v)
			case t == "-f" || t == "-F" || t == "--field" || t == "--raw-field" || t == "--input",
				k == "--field" && eq, k == "--raw-field" && eq, k == "--input" && eq,
				strings.HasPrefix(t, "-f") && len(t) > 2 && !strings.HasPrefix(t, "--"),
				strings.HasPrefix(t, "-F") && len(t) > 2 && !strings.HasPrefix(t, "--"):
				body = true
			case !strings.HasPrefix(t, "-"):
				pos = append(pos, t)
			}
		}
		a := base
		a.Engine = "http"
		if len(pos) > 0 && pos[0] == "api" && method == "" && body {
			method = "POST" // gh api sends a POST once it has fields or an input
		}
		switch {
		case len(pos) > 0 && pos[0] == "api" && method == "DELETE",
			len(pos) > 1 && pos[1] == "delete" && (pos[0] == "repo" || pos[0] == "secret" || pos[0] == "variable" || pos[0] == "release" || pos[0] == "workflow" || pos[0] == "run"):
			a.Class, a.Why = CloudDestructive, name+" "+strings.Join(pos, " ")+" deletes what it names on the remote"
			return a, true
		case len(pos) > 1 && pos[0] == "workflow" && pos[1] == "run", len(pos) > 0 && pos[0] == "api" && method != "" && method != "GET" && method != "HEAD":
			a.Class, a.Why = CloudWrite, name+" "+strings.Join(pos, " ")+" changes the remote or starts its automation"
			return a, true
		}
		return Action{}, false
	}
	if name != "curl" && name != "wget" && name != "http" && name != "https" && name != "xh" && name != "xhs" {
		return Action{}, false
	}
	method, body, signed := httpRequestShape(name, args)
	local := false
	for _, w := range args {
		if strings.Contains(w.Text, "://") || strings.HasPrefix(w.Text, "localhost") {
			t := strings.ToLower(w.Text)
			if strings.Contains(t, "://localhost") || strings.Contains(t, "://127.0.0.1") || strings.Contains(t, "://[::1]") || strings.HasPrefix(t, "localhost") {
				local = true
			} else {
				local = false
				break
			}
		}
	}
	if local && !signed {
		return Action{}, false // a service on this machine: ordinary work
	}
	if method == "" && body {
		method = "POST"
	}
	switch {
	case method == "DELETE":
		a := base
		a.Class, a.Engine = CloudDestructive, "http"
		a.Why = name + " sends a DELETE request, which deletes the resource it names"
		return a, true
	case method != "" && method != "GET" && method != "HEAD" && method != "OPTIONS":
		a := base
		a.Class, a.Engine = CloudWrite, "http"
		a.Why = name + " sends a " + method + " request, which changes the resource it names"
		if signed {
			a.Why = name + " sends a " + method + " request signed with credentials or through a socket, which changes the resource it names"
		}
		return a, true
	}
	return Action{}, false
}

// httpRequestShape reads the request a curl, wget or httpie call sends: its
// method ("" when it is the default for the options given), whether it sends
// a body, form or upload, and whether it is signed or goes through a socket.
// An unresolved method is reported as "UNKNOWN", which is not a read.
var knownHTTPMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "TRACE": true, "CONNECT": true}

func httpRequestShape(name string, args []shell.Word) (method string, body, signed bool) {
	set := func(w shell.Word, v string) {
		if !w.Resolved || v == "" {
			method = "UNKNOWN"
			return
		}
		method = strings.ToUpper(v)
	}
	get := false
	switch name {
	case "curl":
		for i := 0; i < len(args); i++ {
			t := args[i].Text
			if strings.HasPrefix(t, "--") {
				k, v, eq := strings.Cut(t, "=")
				switch k {
				case "--request":
					if eq {
						set(args[i], v)
					} else if i+1 < len(args) {
						i++
						set(args[i], args[i].Text)
					}
				case "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "--json", "--form", "--form-string", "--upload-file":
					body = true
					if !eq && i+1 < len(args) {
						i++
					}
				case "--get":
					get = true
				case "--head":
					method = "HEAD"
				case "--aws-sigv4", "--unix-socket", "--abstract-unix-socket", "--cert":
					signed = true
				}
				continue
			}
			if !strings.HasPrefix(t, "-") || t == "-" {
				continue
			}
			// A short cluster: flags run on until an option that takes a value,
			// whose value is the rest of the cluster or the next word.
			for j := 1; j < len(t); j++ {
				c := t[j]
				rest := t[j+1:]
				takes := strings.IndexByte("dFTXHuAbcCDeEKmoPQrtUwxyYzZ", c) >= 0
				switch c {
				case 'G':
					get = true
				case 'I':
					method = "HEAD"
				}
				if !takes {
					continue
				}
				val := rest
				if val == "" && i+1 < len(args) {
					i++
					val = args[i].Text
				}
				switch c {
				case 'd', 'F', 'T':
					body = true
				case 'X':
					set(args[i], val)
				case 'E':
					signed = true
				}
				break
			}
		}
		if get && method == "" {
			body = false // -G turns the data into a query string
		}
	case "wget":
		for i := 0; i < len(args); i++ {
			k, v, eq := strings.Cut(args[i].Text, "=")
			switch k {
			case "--method":
				if eq {
					set(args[i], v)
				} else if i+1 < len(args) {
					i++
					set(args[i], args[i].Text)
				}
			case "--post-data", "--post-file", "--body-data", "--body-file":
				body = true
			case "--certificate", "--private-key":
				signed = true
			}
		}
		if body && method == "" {
			method = "POST"
		}
	default: // httpie and xh: METHOD URL item...
		first := true
		for _, w := range args {
			t := w.Text
			if strings.HasPrefix(t, "-") {
				continue
			}
			if first {
				first = false
				if m := strings.ToUpper(t); knownHTTPMethods[m] || (t == m && len(t) > 2 && strings.Trim(t, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "") {
					set(w, m)
					continue
				}
			}
			if strings.Contains(t, "://") {
				continue
			}
			// key=value, key:=json and key=@file or key@file send a body;
			// key==value is a query parameter and Header:value a header.
			i := strings.IndexAny(t, "=@:")
			switch {
			case i < 0:
			case strings.HasPrefix(t[i:], "=="), strings.HasPrefix(t[i:], ":") && !strings.HasPrefix(t[i:], ":="):
			default:
				body = true
			}
		}
	}
	return
}
