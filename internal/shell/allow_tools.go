package shell

import "strings"

// Stage 2 of the allow-list (review/v0.6.0/2026-11-05-allow-list-plan.md): the
// programs that had a deny list of options, now an exact list of what is
// understood. Where an option writes a file, the analysis judges that write
// itself only for the options in writes; every other output option is absent.

func init() {
	// curl: one output file (-o, or the remote names of -O) per call, since the
	// analysis judges one; no -K (options from a file), --next (a second request
	// with its own options), --create-dirs, --output-dir, --stderr, --trace*,
	// --dump-header, --cookie-jar, --libcurl, --hsts, --alt-svc, --etag-save
	// (files whose names the write rules do not follow), --engine, --proxy-*
	// helpers and the FTP and mail options.
	allow("curl", newProg(
		"-s -S -f -L -I -i -v -k -g -G -N -O -Z -4 -6 -0 -1 -2 -3 -a -B -j -n -p -q -R -# -h -V -l "+
			"--silent --show-error --fail --fail-with-body --location --location-trusted --head --include --verbose --insecure --globoff --get "+
			"--no-buffer --parallel --parallel-immediate --compressed --http1.0 --http1.1 --http2 --http2-prior-knowledge --http3 --ipv4 --ipv6 "+
			"--tlsv1 --tlsv1.0 --tlsv1.1 --tlsv1.2 --tlsv1.3 --ssl --ssl-reqd --no-keepalive --no-sessionid --netrc --netrc-optional --proxytunnel "+
			"--disable --remote-time --progress-bar --no-progress-meter --anyauth --basic --digest --ntlm --negotiate --append --use-ascii "+
			"--junk-session-cookies --path-as-is --tr-encoding --raw --no-alpn --tcp-nodelay --tcp-fastopen --ignore-content-length --crlf "+
			"--disallow-username-in-url --styled-output --no-styled-output --suppress-connect-headers --post301 --post302 --post303 --http0.9 "+
			"--ssl-no-revoke --cert-status --retry-connrefused --retry-all-errors --list-only --help --version --remote-name --remote-name-all "+
			"--proxy-insecure --proxy-anyauth --proxy-basic --proxy-digest --proxy-negotiate --proxy-ntlm --no-clobber",
		"-H -X -d -F -u -A -e -m -b -T -x -U -r -E -w -o -C -y -Y -z -P "+
			"--header --request --data --data-raw --data-binary --data-ascii --data-urlencode --json --form --form-string --user --user-agent "+
			"--referer --max-time --cookie --upload-file --proxy --proxy-user --range --cert --write-out --output --continue-at --speed-time "+
			"--speed-limit --time-cond --connect-timeout --retry --retry-delay --retry-max-time --max-redirs --max-filesize --limit-rate "+
			"--resolve --connect-to --cacert --capath --key --pass --cert-type --key-type --crlfile --pinnedpubkey --noproxy --proxy-header "+
			"--proxy-cacert --proxy-cert --proxy-key --oauth2-bearer --aws-sigv4 --unix-socket --abstract-unix-socket --interface "+
			"--local-port --dns-servers --doh-url --ciphers --tls13-ciphers --curves --tls-max --expect100-timeout --url --url-query "+
			"--keepalive-time --happy-eyeballs-timeout-ms --request-target --service-name --proxy-service-name").
		withOnce("-o --output -O --remote-name --remote-name-all").withWrites("-o --output -O --remote-name --remote-name-all").
		withOutputs("-o --output -D --dump-header -c --cookie-jar --trace --trace-ascii --stderr --libcurl").
		withValOK(func(opt string, v Word) string {
			switch opt {
			case "-w", "--write-out":
				// %output{FILE} writes a file, and @FILE reads the format from one.
				if !v.Resolved || strings.Contains(v.Text, "%output") || strings.HasPrefix(v.Text, "@") {
					return "a curl --write-out format that can write a file"
				}
			case "-o", "--output":
				// #1 names an output file per glob match of the URL.
				if strings.Contains(v.Text, "#") {
					return "a curl output name with a glob variable"
				}
			}
			return ""
		}))

	// wget: -O and -P are the writes the analysis follows; -o and -a (log
	// files), -i (URLs from a file), -b (a log file), recursion and mirroring
	// (many files), --content-disposition and --trust-server-names (a name the
	// server chooses), --save-cookies, -e and --config are absent.
	allow("wget", newProg(
		"-q -v -nv -c -N -S -nc -4 -6 -h -V --quiet --verbose --no-verbose --continue --timestamping --server-response --spider --no-clobber "+
			"--no-check-certificate --no-cache --no-cookies --no-proxy --no-dns-cache --inet4-only --inet6-only --content-on-error "+
			"--auth-no-challenge --no-http-keep-alive --show-progress --https-only --no-hsts --retry-connrefused --http-keep-alive "+
			"--keep-session-cookies --ignore-length --random-wait --help --version --no-verbose --no-parent",
		"-O -P -T -t -w -U -Q --output-document --directory-prefix --timeout --tries --wait --user-agent --header --user --password "+
			"--http-user --http-password --referer --post-data --post-file --body-data --body-file --method --load-cookies --certificate "+
			"--private-key --ca-certificate --ca-directory --connect-timeout --dns-timeout --read-timeout --limit-rate --bind-address "+
			"--waitretry --max-redirect --compression --progress --secure-protocol --quota").
		withOnce("-O --output-document").withWrites("-O --output-document -P --directory-prefix").
		withOutputs("-O --output-document -o --output-file -a --append-output"))

	allow("zip", newProg(
		"-r -q -v -j -J -y -X -D -u -f -g -m -d -e -FS -9 -8 -7 -6 -5 -4 -3 -2 -1 -0 --recurse-paths --quiet --verbose --junk-paths --symlinks --no-extra "+
			"--no-dir-entries --update --freshen --grow --move --delete --encrypt --filesync",
		"-x -i -P -n -t -tt --exclude --include --password").withNum())

	allow("yq", newProg(
		"-r -P -C -M -N -n -e -j -I -i -0 -h -V -v --unwrapScalar --prettyPrint --colors --no-colors --null-input --exit-status --inplace "+
			"--no-doc --verbose --version --help --front-matter",
		"-o -p -f --output-format --input-format --expression --from-file --indent --xml-attribute-prefix --xml-content-name --csv-auto-parse "+
			"--properties-separator").withNum())

	rgFlags := "-i -S -s -n -N -H -I -l -L -c -o -q -v -w -x -F -P -U -a -u -p -0 -. -h -V " +
		"--hidden --no-ignore --no-ignore-vcs --no-ignore-parent --no-ignore-dot --no-ignore-global --no-ignore-files --no-ignore-exclude " +
		"--follow --text --binary --count --count-matches --files --files-with-matches --files-without-match --fixed-strings --ignore-case " +
		"--smart-case --case-sensitive --invert-match --line-number --no-line-number --no-filename --with-filename --only-matching --quiet " +
		"--word-regexp --line-regexp --multiline --multiline-dotall --pcre2 --null --null-data --heading --no-heading --column --vimgrep " +
		"--json --stats --trim --pretty --no-messages --no-config --one-file-system --crlf --debug --trace --type-list --include-zero " +
		"--line-buffered --block-buffered --no-unicode --unicode --version --help --no-require-git --no-mmap --mmap --sort-files " +
		"--no-column --no-stats --no-heading --no-ignore-messages --auto-hybrid-regex --no-pcre2 --no-multiline"
	rgVals := "-e -f -g -t -T -A -B -C -m -d -E -r -M -j " +
		"--regexp --file --glob --iglob --type --type-not --after-context --before-context --context --max-count --max-depth --maxdepth " +
		"--max-filesize --encoding --replace --max-columns --path-separator --context-separator --field-context-separator --field-match-separator " +
		"--type-add --type-clear --ignore-file --threads --sort --sortr --color --colors --regex-size-limit --dfa-size-limit --engine " +
		"--hyperlink-format --pre-glob-none"
	allow("rg", newProg(rgFlags, rgVals).withNum())

	// printf has no option of its own; bash's builtin takes -v VAR.
	allow("printf", newProg("--help --version", ""))

	allow("actionlint", newProg("-oneline -verbose -color -no-color -version -debug -stdin", "-ignore -format -config-file"))
	allow("tflint", newProg("--recursive --no-color --color --force --version -v --help -h",
		"--format -f --enable-rule --disable-rule --only --var-file --var --chdir --filter --minimum-failure-severity --call-module-type --max-workers").
		withOutputs("--out --output-file"))
}
