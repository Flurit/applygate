package shell

import (
	"sort"
	"testing"
)

// The programs that keep "any arguments" are the audited ones in inert, plus
// the programs whose shapes are written elsewhere; adding a name to the nil set
// means auditing it.
func TestNilShapesAreTheAuditedOnes(t *testing.T) {
	elsewhere := toSet("terraform", "tofu", "applygate", "env")
	var extra []string
	for n, s := range shapes {
		if s == nil && !inert[n] && !elsewhere[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("programs with a nil shape that are not in the audited list: %v", extra)
	}
	for n := range inert {
		if s, ok := shapes[n]; !ok || s != nil {
			t.Errorf("%s is listed as inert but has a shape", n)
		}
	}
}

func plainCall(t *testing.T, cmd string) bool {
	t.Helper()
	ok, _ := PlainShape(cmd, analyze(cmd, "/r"))
	return ok
}

func TestAllowListedProgramsOnlyTakeListedOptions(t *testing.T) {
	plain := []string{
		"rm -rf build", "rm -f a b", "mkdir -p out/x", "touch a", "chmod -R go-w dir", "chmod -x run.sh", "chmod 644 a",
		"ln -s a b", "cp -r a b", "cp -t dir a b", "mv -f a b", "tee -a log", "echo x | tee out.txt",
		"sort -u a", "sort -k2,2 -t, a", "sort -n a", "uniq -c a", "tree -L 2", "diff -u a b", "diff -r a b",
		"xxd a", "xxd -r -p a", "base64 -d a", "gzip -dc a.gz", "gzip -c a", "gzip -l a.gz", "gunzip -c a.gz", "unzip -l a.zip", "unzip -p a.zip f", "unzip -o a.zip", "unzip -d out a.zip",
		"date +%Y", "date -u +%s", "hostname", "file -b a", "gofmt -l .", "gofmt -d a.go", "tfsec . --format json",
		"gsutil ls gs://b", "find . -name '*.tf' -type f", "find . -maxdepth 2 -not -path './.git/*' -print", "find . \\( -name a -o -name b \\) -print0",
		"find . -newer a -size +1M", "find dir -mtime -7",
	}
	for _, c := range plain {
		if !plainCall(t, c) {
			ok, why := PlainShape(c, analyze(c, "/r"))
			t.Errorf("%q should be plain: %v %s", c, ok, why)
		}
	}
	notPlain := []string{
		// options that write a file or run a program, and spellings of them
		"sort -o out a", "sort -oout a", "sort --output=out a", "sort --compress-program=sh a", "sort --compress a", "sort -T /tmp a",
		"uniq a out", "tree -o out", "tree --output=out", "tree -H x", "diff -l a b", "diff --paginate a b",
		"xxd -r a out", "base64 -o out a", "base64 -i a -o out",
		"gzip a", "gunzip a.gz", "gzip -k a", "unzip -O cp866 a.zip", "unzip --foo a.zip",
		"date -s 2020-01-01", "date --set=x", "date 110512302026", "hostname newname", "file -C", "gofmt -w a.go", "gofmt -cpuprofile p a.go",
		"tfsec --out r.json .", "gsutil rm gs://b/x", "gsutil -o x:y ls", "gsutil cp a gs://b",
		"find . -exec rm {} ;", "find . -execdir sh ;", "find . -ok rm {} ;", "find . -delete", "find . -fprint out", "find . -fprint0 out", "find . -fprintf out x",
		"find . -fls out", "find -P . -delete", "find . -name a -exec sh -c x ;", "find . -newerXY x", "find . -foo",
		"rm --no-preserve-root -rf /", "rm --recur a", "cp --rec a b", "cp -b a b", "cp --backup a b", "cp -S x a b", "mv -S x a b", "ln --sym a b",
		"mkdir --mod=0 a", "chmod --silly a", "tee --append x -z",
		// an unresolved word may be an option
		"sort $X a", "tree $X", "find $X -name a", "find . $X", "uniq $X", "xxd $X",
	}
	for _, c := range notPlain {
		if plainCall(t, c) {
			t.Errorf("%q should not be plain", c)
		}
	}
}

func TestAllowListLooseProgramsTakeVariableOperands(t *testing.T) {
	for _, c := range []string{`rm -rf "$DIR"`, `mkdir -p "$d/x"`, `cp "$a" "$b"`, `mv "$a" "$b"`, `touch "$f"`, `chmod +x "$f"`, `ln -s "$a" "$b"`} {
		if !plainCall(t, c) {
			ok, why := PlainShape(c, analyze(c, "/r"))
			t.Errorf("%q: %v %s", c, ok, why)
		}
	}
}
