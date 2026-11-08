package guard

import (
	"os"
	"path/filepath"
	"testing"
)

// Removing a directory can weaken the guard only through a guard file that
// is there and whose loss weakens it; writing or extracting into the
// directory counts every guard file it could hold.
func TestRemovalTouchesCountsOnlyWhatRemovingWeakens(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, ".claude", "settings.json")
	providers := filepath.Join(root, ".terraform", "providers")
	hooks := filepath.Join(root, ".github", "hooks")
	s := New([]string{"**/.claude/settings.json", "**/.terraform/providers/**", "**/.github/hooks/**"},
		[]string{settings, providers, hooks}).PlantOnly([]string{"**/.terraform/providers/**"}, []string{providers})
	os.MkdirAll(filepath.Join(providers, "x"), 0o755)
	os.MkdirAll(filepath.Join(root, ".github", "workflows"), 0o755)

	for _, c := range []struct {
		p              string
		touch, removal bool
	}{
		{root, true, false}, // settings.json is not there yet
		{filepath.Join(root, ".terraform"), true, false}, // providers only matter for what is placed there
		{filepath.Join(providers, "x"), true, false},     // a plant-only guard file by name
		{filepath.Join(root, ".github"), true, false},    // .github/hooks is not there
		{filepath.Join(root, ".claude"), true, false},    // nothing in it yet
		{filepath.Join(root, "src"), false, false},       // holds no guard file
		{settings, true, true},                           // a hook settings file by name, there or not
	} {
		if got := s.Touches(c.p); got != c.touch {
			t.Errorf("Touches(%s) = %v, want %v", c.p, got, c.touch)
		}
		if got := s.RemovalTouches(c.p); got != c.removal {
			t.Errorf("RemovalTouches(%s) = %v, want %v", c.p, got, c.removal)
		}
	}
	os.MkdirAll(filepath.Dir(settings), 0o755)
	os.WriteFile(settings, []byte("{}"), 0o644)
	os.MkdirAll(hooks, 0o755)
	for _, p := range []string{root, filepath.Join(root, ".claude"), filepath.Join(root, ".github")} {
		if !s.RemovalTouches(p) {
			t.Errorf("RemovalTouches(%s) = false once the guard file is there", p)
		}
	}
}

// A soft target (a git root or session directory without a config) counts
// for Touches but not TouchesHard; a pattern names a guard file anywhere.
func TestSoftTargetsAreNotHard(t *testing.T) {
	cfgRoot, sess := t.TempDir(), t.TempDir()
	hard := filepath.Join(cfgRoot, ".claude", "settings.json")
	soft := filepath.Join(sess, ".claude", "settings.json")
	s := New([]string{"**/.claude/settings.json"}, []string{hard, soft}).Soft([]string{soft})
	if !s.Touches(sess) || s.TouchesHard(sess) {
		t.Errorf("session root: Touches %v, TouchesHard %v; want true, false", s.Touches(sess), s.TouchesHard(sess))
	}
	if !s.TouchesHard(cfgRoot) {
		t.Errorf("config root: TouchesHard false")
	}
	if !s.TouchesHard(soft) {
		t.Errorf("a soft guard file by name: TouchesHard false (the pattern names it)")
	}
	os.MkdirAll(filepath.Dir(soft), 0o755)
	os.WriteFile(soft, []byte("{}"), 0o644)
	if !s.RemovalTouches(sess) || s.RemovalTouchesHard(sess) {
		t.Errorf("session root removal: %v, hard %v; want true, false", s.RemovalTouches(sess), s.RemovalTouchesHard(sess))
	}
}
