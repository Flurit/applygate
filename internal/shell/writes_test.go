package shell

import (
	"slices"
	"strings"
	"testing"
)

func words(s string) []Word {
	var out []Word
	for _, f := range strings.Fields(s) {
		out = append(out, lit(f))
	}
	return out
}

func writtenTexts(name, args string) []string {
	var out []string
	for _, w := range Writes(name, words(args)) {
		out = append(out, w.Text)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// The write rules read a plain call as the matcher reads it, and a call that
// is not plain leniently, counting every operand that may be written.
func TestWriteRulesReadTheMatchersParse(t *testing.T) {
	cases := []struct {
		name, args string
		want       []string
	}{
		// Operands after -- that start with a dash are files.
		{"rm", "-f -- -rf .applygate.yaml", []string{"-rf", ".applygate.yaml"}},
		{"rm", "-rf build", []string{"build"}},
		// cp writes into -t's directory, given in any spelling the matcher reads.
		{"cp", "-t .claude a b", []string{".claude"}},
		{"cp", "-at .claude a b", []string{".claude"}},
		{"cp", "--target-directory=.claude a", []string{".claude"}},
		{"cp", "a b dest", []string{"dest"}},
		// Not plain (--sparse is not listed): every operand but the first.
		{"cp", "src dest --sparse always", []string{"always", "dest"}},
		{"mv", "a b", []string{"a", "b"}},
		{"ln", "-s target", []string{"target"}},
		{"ln", "-sf /etc/x link", []string{"/etc/x", "link"}},
		{"chmod", "644 a b", []string{"a", "b"}},
		{"chmod", "--reference=r a", []string{"a"}},
		{"mkdir", "-p a/b", nil}, // created, not replaced: the analyzer records it
		{"tee", "-a log out", []string{"log", "out"}},
		{"touch", "terraform.tfstate", []string{"terraform.tfstate"}},
		// curl: -O inside a cluster is the matcher's -O.
		{"curl", "-sO https://h/x/terraform.tfstate", []string{".", "terraform.tfstate"}},
		{"curl", "-so out.json https://h/a", []string{"out.json"}},
		{"curl", "-s https://h/a", nil},
		{"wget", "-P dl https://h/f.zip", []string{"dl", "dl/f.zip"}},
		{"wget", "-O - https://h/f.zip", nil},
		{"unzip", "-l a.zip", nil},
		{"unzip", "a.zip -d out", []string{"out"}},
		{"unzip", "a.zip", []string{"."}},
		{"zip", "-r backup .", []string{"backup", "backup.zip"}},
		{"zip", "-m a.zip x", []string{"a.zip", "x"}},
		{"yq", "-i .a=1 f.yaml", []string{".a=1", "f.yaml"}},
		{"yq", ".a f.yaml", nil},
		{"gzip", "-c f", nil},
		{"gunzip", "--weird terraform.tfstate.gz", []string{"terraform.tfstate", "terraform.tfstate.gz"}},
		{"uniq", "in out", []string{"out"}},
		{"sort", "-o out in", []string{"out"}},
		{"sort", "-u in", nil},
		// tar: in the old style the cluster's values are the following words
		// in order; after a dash the rest of the word is the value (getopt).
		{"tar", "cfC out.tar dir .", []string{"out.tar"}},
		{"tar", "xfC a.tar dir", []string{"dir"}},
		{"tar", "-cfC out.tar dir .", []string{"C"}},
		{"tar", "xf a.tar", []string{"."}},
		{"tar", "-xzf a.tgz -C /tmp/x", []string{"/tmp/x"}},
		{"tar", "-Cdest -xf a.tar", []string{"dest"}},
		{"tar", "--extract --file=a.tar --directory dest", []string{"dest"}},
		{"tar", "-czf backup.tgz .terraform", []string{"backup.tgz"}},
		{"tar", "-tf a.tar", nil},
		{"7z", "x a.7z -oout", []string{"out"}},
		{"7z", "a out.7z dir", []string{"out.7z"}},
		{"dd", "if=a of=b", []string{"b"}},
		{"openssl", "enc -in a -out b", []string{"b"}},
		{"sed", "-Ei s/a/b/ f", []string{"f", "s/a/b/"}},
		{"sed", "s/a/b/ f", nil},
		{"find", ". -name x -delete", []string{"."}},
		{"find", "a b -exec rm {} +", []string{"a", "b"}},
		{"find", ". -name x -exec grep y {} +", nil},
		{"find", ". -fprint out", []string{"out"}},
		{"rsync", "-a src/ host:/backup", nil},
		{"rsync", "-a src/ dst/", []string{"dst/"}},
		{"scp", "host:/x/terraform.tfstate .", []string{"."}},
		{"aws", "s3 cp s3://b/k ./local", []string{"./local"}},
		{"aws", "s3api get-object --bucket b --key k out.json", []string{"out.json"}},
		{"aws", "ec2 describe-instances", nil},
		{"git", "checkout main", []string{"."}},
		{"cat", "a b", nil},
		{"python3", "x.py", nil},
	}
	for _, c := range cases {
		got := writtenTexts(c.name, c.args)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s %s: writes %q, want %q", c.name, c.args, got, c.want)
		}
	}
}

// Every program the matcher can call plain and that writes an operand has a
// write rule, so a protected tier never allows a write the classifier does not
// see. A program with an entry and no rule must only print.
func TestPlainWritersHaveARule(t *testing.T) {
	writersWithEntries := []string{"rm", "mkdir", "touch", "chmod", "ln", "cp", "mv", "tee", "unzip", "zip", "yq", "curl", "wget", "gzip", "gunzip", "uniq", "xxd", "sort", "base64"}
	for _, n := range writersWithEntries {
		if allowProgs[n] == nil {
			t.Errorf("%s has no allow-list entry; update this test", n)
		}
		if writeRules[n] == nil {
			t.Errorf("%s has an allow-list entry and writes, but no write rule", n)
		}
	}
	for _, n := range []string{"tar", "sed", "find", "aws", "git"} {
		if !HasWriteRule(n) {
			t.Errorf("%s has no write rule", n)
		}
	}
}

// Removes is what a call only removes or moves away: rm's operands, mv's
// sources (not its destination, and nothing when read leniently, where an
// operand may be the destination), find -delete's starting points.
func TestRemovesIsOnlyWhatIsRemoved(t *testing.T) {
	cases := []struct {
		name, args string
		want       []string
	}{
		{"rm", "-rf .terraform build", []string{".terraform", "build"}},
		{"rmdir", "empty", []string{"empty"}},
		{"mv", ".terraform /tmp/old", []string{".terraform"}},
		{"mv", "-t /tmp .claude a", []string{".claude", "a"}},
		{"mv", "staged .claude", []string{"staged"}},
		{"mv", "-S .claude x y", nil}, // -S is not listed: read leniently
		{"ln", "-sf a b", nil},
		{"chmod", "-R 000 .claude", nil},
		{"find", ". -name x -delete", []string{"."}},
		{"find", "a -exec rm {} +", []string{"a"}},
		{"find", "a -exec mv {} /tmp +", nil},
		{"zip", "-m a.zip x", []string{"x"}},
		{"cp", "a b", nil},
		{"tar", "-xf a.tar", nil},
	}
	for _, c := range cases {
		var got []string
		for _, w := range Removes(c.name, words(c.args)) {
			got = append(got, w.Text)
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s %s: removes %q, want %q", c.name, c.args, got, c.want)
		}
	}
}
