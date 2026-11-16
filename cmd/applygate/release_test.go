package main

import (
	"os"
	"regexp"
	"testing"
)

// The Action installs the release named by its version input's default. A
// workflow that says `uses: Flurit/applygate@vX.Y.Z` reads action.yml from
// that tag, so the default has to name the release in the commit the tag is
// made on: v0.6.0 and v0.6.1 were tagged with the release before, and
// installed it. The newest section of the changelog is the release being
// prepared or the last one made, so the two must agree
// (scripts/bump-version-refs.sh --action, docs/project/RELEASE.md).
func TestActionInstallsTheNewestRelease(t *testing.T) {
	action, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	changelog, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	def := regexp.MustCompile(`(?m)^  version:\n(?:    .*\n)*?    default: (v\S+)$`).FindSubmatch(action)
	if def == nil {
		t.Fatal("action.yml: the version input has no default")
	}
	newest := regexp.MustCompile(`(?m)^## (v[0-9]+\.[0-9]+\.[0-9]+)\b`).FindSubmatch(changelog)
	if newest == nil {
		t.Fatal("CHANGELOG.md: no release section")
	}
	if string(def[1]) != string(newest[1]) {
		t.Errorf("action.yml installs %s by default, and the newest release in CHANGELOG.md is %s: run scripts/bump-version-refs.sh --action %s", def[1], newest[1], newest[1])
	}
}
