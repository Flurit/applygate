package hook

import "testing"

func TestModuleVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v0.3.0":                               "0.3.0",
		"":                                     "",
		"(devel)":                              "",
		"v0.3.1-0.20261030120000-abcdef123456": "",
		"v0.3.0+dirty":                         "",
	} {
		if got := moduleVersion(in); got != want {
			t.Errorf("moduleVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
