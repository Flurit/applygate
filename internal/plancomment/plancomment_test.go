package plancomment

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/plangate"
	"github.com/Flurit/applygate/internal/policy"
)

// judge evaluates a plan as plan-check does and returns the comment input.
func judge(t *testing.T, planJSON []byte, tier config.Tier) Input {
	t.Helper()
	res, err := plangate.Evaluate(plangate.Input{PlanJSON: planJSON, MaxDestroy: -1}, plangate.DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	return Input{Key: "envs/prod/tfplan", Workspace: "default", Tier: tier, TierSet: true, Version: "v0.0.0",
		Verdict: policy.SavedPlanVerdict(res, tier), Result: res}
}

func realPlan(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../review/real_plan/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// plan builds plan JSON with one resource change per entry.
type change struct {
	addr, typ string
	actions   []string
}

func plan(t *testing.T, changes []change) []byte {
	t.Helper()
	var rcs []map[string]any
	for _, c := range changes {
		rcs = append(rcs, map[string]any{
			"address": c.addr, "mode": "managed", "type": c.typ, "name": "x",
			"change": map[string]any{"actions": c.actions, "before": map[string]any{}, "after": map[string]any{}},
		})
	}
	b, err := json.Marshal(map[string]any{"format_version": "1.2", "planned_values": map[string]any{}, "resource_changes": rcs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustContain(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Errorf("the comment lacks %q:\n%s", w, body)
		}
	}
}

func TestBlockNamesTheStatefulResourceFirst(t *testing.T) {
	in := judge(t, realPlan(t, "delete_real_shape.show.json"), config.Protected)
	body := Render(in)
	mustContain(t, body,
		"### applygate plan check: ⛔ block",
		"Plan `envs/prod/tfplan` · tier **protected** (set for this check) · 2 changes, 1 destroyed, 0 replaced",
		"**Why block**",
		"  - `aws_db_instance.main (aws_db_instance) is destroyed`",
		"A protected tier blocks any destroy or replace; this plan has 1 (1 named above)",
		"(`protection-removed`)",
		"**Also found**",
	)
	stateful := strings.Index(body, "`stateful-destroyed`")
	for _, later := range []string{"any destroy or replace", "`protection-removed`", "`unknown-watched`"} {
		if i := strings.Index(body, later); i < stateful {
			t.Errorf("%q comes before the destroyed stateful resource:\n%s", later, body)
		}
	}
	if !strings.HasPrefix(body, Marker("envs/prod/tfplan", "default")+"\n") {
		t.Errorf("the comment does not start with its marker:\n%s", body)
	}
}

func TestAskSaysWhy(t *testing.T) {
	in := judge(t, realPlan(t, "delete_real_shape.show.json"), config.Standard)
	body := Render(in)
	mustContain(t, body,
		"### applygate plan check: ⚠️ ask",
		"a person should review this plan before it is applied",
		"**Why ask**",
		"A standard tier asks about any destroy or replace",
		"`aws_db_instance.main (aws_db_instance) is destroyed`",
	)
	// A create with no safety net asks in a protected tier, with no destroy.
	in = judge(t, realPlan(t, "create.show.json"), config.Protected)
	body = Render(in)
	mustContain(t, body, "⚠️ ask", "(`stateful-unprotected-create`)", "`aws_db_instance.main: created with deletion protection off and the final snapshot skipped`")
	if strings.Contains(body, "any destroy or replace") {
		t.Errorf("a plan without a destroy gives one as a reason:\n%s", body)
	}
}

func TestAllowIsShortAndStillListsWhatWasFound(t *testing.T) {
	in := judge(t, plan(t, []change{{"aws_s3_bucket.assets", "aws_s3_bucket", []string{"create"}}}), config.Standard)
	body := Render(in)
	mustContain(t, body, "### applygate plan check: ✅ allow", "Nothing in this plan needs a review", "1 change, 0 destroyed, 0 replaced")
	for _, no := range []string{"**Why", "<details>", "Found, and allowed"} {
		if strings.Contains(body, no) {
			t.Errorf("an allow with no finding has %q:\n%s", no, body)
		}
	}
	if n := strings.Count(body, "\n"); n > 8 {
		t.Errorf("an allow with no finding is %d lines:\n%s", n, body)
	}
	// In a disposable tier a destroyed database is allowed, and still named.
	in = judge(t, realPlan(t, "delete_real_shape.show.json"), config.Disposable)
	body = Render(in)
	mustContain(t, body, "✅ allow", "**Found, and allowed in this tier**", "<details>", "Destroyed (1)", "- `aws_db_instance.main`")
	if strings.Contains(body, "**Why") {
		t.Errorf("an allow gives reasons for a verdict it did not reach:\n%s", body)
	}
}

func TestResolvedTierNamesTheEnvironment(t *testing.T) {
	in := judge(t, realPlan(t, "create.show.json"), config.Protected)
	in.TierSet, in.Env, in.Matched = false, "prod", []string{"path envs/prod/**"}
	mustContain(t, Render(in), "environment `prod` (`path envs/prod/**`) · tier **protected** ·")
	in.Env, in.Matched = "unknown", []string{"no environment matched; strict mode treats it as protected"}
	body := Render(in)
	mustContain(t, body, "tier **protected** (`no environment matched; strict mode treats it as protected`)")
	if strings.Contains(body, "environment `unknown`") {
		t.Errorf("a directory no environment matches is given an environment:\n%s", body)
	}
	in.Untrusted = []string{"/repo/.applygate.yaml"}
	mustContain(t, Render(in), "tier **protected** (the config was not read)", "The config `/repo/.applygate.yaml` has no trust record", "are not applied, and the tier is protected.", "`trust-config: true`")
	in.TierSet = true
	if body := Render(in); strings.Contains(body, "the tier is protected") || !strings.Contains(body, "are not applied. In CI") {
		t.Errorf("a tier set for the check is said to be protected because of the config:\n%s", body)
	}
	in.TierSet = false
	in.Workspace = "payments"
	mustContain(t, Render(in), "workspace `payments`")
}

func TestLongPlanIsCollapsedAndFitsAComment(t *testing.T) {
	var changes []change
	for i := 0; i < 6000; i++ {
		typ := "aws_instance"
		if i%3 == 0 {
			typ = "aws_db_instance"
		}
		changes = append(changes, change{fmt.Sprintf("module.fleet[%q].%s.node_with_a_long_name_%04d", strings.Repeat("region-", 6), typ, i), typ, []string{"delete"}})
	}
	in := judge(t, plan(t, changes), config.Protected)
	body := Render(in)
	if len(body) > 65000 {
		t.Fatalf("the comment is %d bytes; GitHub refuses a body over 65536 characters", len(body))
	}
	mustContain(t, body, "⛔ block", "6000 destroyed", "and 1995 more, in the list below", "<details>", "</details>", "more: too long for a comment, the job log has them all.")
	// What is read without opening the block stays short.
	visible := body[:strings.Index(body, "<details>")]
	if n := strings.Count(visible, "\n"); n > 40 {
		t.Errorf("%d lines come before the collapsed block:\n%s", n, visible)
	}
	if strings.Count(body, "<details>") != 1 || strings.Count(body, "</details>") != 1 {
		t.Errorf("the collapsed block is not opened and closed once")
	}
}

// stripCode removes the code spans of one line as Markdown reads them: a run
// of backticks opens a span that the next run of the same length closes.
func stripCode(line string) string {
	var out strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			out.WriteByte(line[i])
			i++
			continue
		}
		j := i
		for j < len(line) && line[j] == '`' {
			j++
		}
		n := j - i
		closeAt := -1
		for k := j; k < len(line); {
			if line[k] != '`' {
				k++
				continue
			}
			m := k
			for m < len(line) && line[m] == '`' {
				m++
			}
			if m-k == n {
				closeAt = m
				break
			}
			k = m
		}
		if closeAt < 0 {
			out.WriteString(line[i:j]) // an unmatched run is literal text
			i = j
			continue
		}
		out.WriteString("CODE")
		i = closeAt
	}
	return out.String()
}

var hostile = []string{
	"aws_db_instance.a[\"](https://evil.example/x) @octocat #1 <script>alert(1)</script>\"]",
	"aws_db_instance.b[\"`](https://evil.example/y)`\"]",
	"aws_db_instance.c[\"```\\n### not a heading ``\"]",
	"aws_db_instance.d[\"x\n\n### injected heading\n\n- [ ] task @octocat\"]",
	"aws_db_instance.e[\"--> </details> <details open><summary>x</summary> <!-- \"]",
	"aws_db_instance.f[\"![img](https://evil.example/track.png) <img src=x onerror=alert(1)>\"]",
	"aws_db_instance.g[\"\u202egnp.exe\u200b\u2066 \x1b[31mred\x07\"]",
	"aws_db_instance.h[\"" + Marker("envs/prod/tfplan", "default") + "\"]",
	"`aws_db_instance.i`",
	"aws_db_instance.j[\"::error::x %0A| table | cell |\"]",
	"aws_db_instance." + strings.Repeat("k", 5000),
	"aws_db_instance.l[\"\xff\xfe bad utf8\"]",
}

// Text from the plan is only ever inside a code span: outside the spans the
// comment holds applygate's own words and nothing a resource address,
// environment name, path or error message brought.
func TestHostilePlanTextStaysInsideCodeSpans(t *testing.T) {
	var changes []change
	for _, a := range hostile {
		changes = append(changes, change{a, "aws_db_instance", []string{"delete", "create"}})
	}
	for _, tier := range []config.Tier{config.Protected, config.Standard, config.Disposable} {
		in := judge(t, plan(t, changes), tier)
		in.TierSet = false
		in.Key = "envs/`prod`/<b>tfplan</b> @octocat"
		in.Workspace = "ws](https://evil.example) @octocat"
		in.Env = "prod <img src=x> @octocat"
		in.Matched = []string{"path envs/**`` [x](https://evil.example)"}
		in.Untrusted = []string{"/repo/<script>/.applygate.yaml\n### heading"}
		checkHostile(t, Render(in), in)
	}
	in := Input{Key: hostile[0], Workspace: hostile[3], Err: "open " + hostile[4] + "\n" + hostile[1] + ": no such file", Version: "v0 <b>@octocat</b>"}
	body := Render(in)
	checkHostile(t, body, in)
	if strings.Contains(body, "v0 ") {
		t.Errorf("a version that is not one is shown:\n%s", body)
	}
}

var ownLine = regexp.MustCompile(`^(|### applygate plan check: \S+ (allow|ask|block|error)|\*\*(Why (ask|block)|Also found|Found, and allowed in this tier)\*\*|(- |  - |> |Plan |The rules |Nothing in |applygate could not |\*\*(critical|high|info)\*\* |Destroyed \(|Replaced \(|A (protected|standard) tier |\d+ lines? more: ).*|<details>|<summary>The full lists \(\d+ lines?\)</summary>|</details>|<sub>applygate .*</sub>)$`)

func checkHostile(t *testing.T, body string, in Input) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if lines[0] != Marker(in.Key, in.Workspace) {
		t.Fatalf("the first line is not the marker: %q", lines[0])
	}
	details := 0
	for i, line := range lines[1:] {
		for _, r := range line {
			if r < 0x20 || r == 0x7f || r == 0x202e || r == 0x200b && !strings.Contains(line, "<sub>") || r == 0x2066 || r == 0xfffe {
				t.Errorf("line %d has the character %U: %q", i+2, r, line)
			}
		}
		rest := stripCode(line)
		for _, bad := range []string{"@", "<script", "<img", "<b>", "http", "](", "![", "-->", "<!--", "###", "[ ]", "evil", "octocat", "::error", "| table", "onerror", "gnp", "applygate:plan-check"} {
			if strings.Contains(rest, bad) && !(bad == "###" && i == 0) {
				t.Errorf("line %d has %q outside a code span: %q", i+2, bad, line)
			}
		}
		if strings.Contains(rest, "`") {
			t.Errorf("line %d has a backtick that closes no span: %q", i+2, line)
		}
		if !ownLine.MatchString(rest) {
			t.Errorf("line %d is not one of applygate's own: %q", i+2, line)
		}
		if strings.Contains(rest, "<details") || strings.Contains(rest, "</details") {
			details++
		}
		if len(line) > 4000 {
			t.Errorf("line %d is %d bytes long", i+2, len(line))
		}
	}
	if details != 0 && details != 2 {
		t.Errorf("the collapsed block is opened or closed %d times", details)
	}
}

func TestCodeSpanCannotBeClosedByItsText(t *testing.T) {
	for _, s := range []string{"a", "a`b", "`", "``", "a``b`c", "`lead", "trail`", "```go\nx\n```", " spaced ", "a\tb\r\nc", "", "\x00\x1b", strings.Repeat("`", 50)} {
		span := code(s)
		if got := stripCode(span); got != "CODE" {
			t.Errorf("code(%q) = %q, which Markdown reads as %q", s, span, got)
		}
		if strings.ContainsAny(span, "\n\r\t\x00\x1b") {
			t.Errorf("code(%q) = %q keeps a control character", s, span)
		}
	}
	if got := code(""); got != "`(empty)`" {
		t.Errorf("code of nothing = %q", got)
	}
}

func TestTextEscapesMarkup(t *testing.T) {
	got := text("see <b>x</b> & [a](http://b) @octocat #12 *bold* `c`")
	for _, bad := range []string{"<b>", "](", "@octocat", "#12", " *bold*", " `c`"} {
		if strings.Contains(got, bad) {
			t.Errorf("text() keeps %q: %s", bad, got)
		}
	}
}

func TestMarkerIsStableAndSaysNothingOfTheKey(t *testing.T) {
	a := Marker("envs/prod/tfplan", "default")
	if a != Marker("envs/prod/tfplan", "default") {
		t.Error("the same plan and workspace give two markers")
	}
	if !regexp.MustCompile(`^<!-- applygate:plan-check [0-9a-f]{16} -->$`).MatchString(a) {
		t.Errorf("marker %q", a)
	}
	for _, other := range []string{Marker("envs/stage/tfplan", "default"), Marker("envs/prod/tfplan", "payments"), Marker("envs/prod/tfplandefault", "")} {
		if other == a {
			t.Error("two plans or workspaces share a marker")
		}
	}
	if m := Marker("x --> <script>", "\n"); !regexp.MustCompile(`^<!-- applygate:plan-check [0-9a-f]{16} -->$`).MatchString(m) {
		t.Errorf("a hostile key reaches the marker: %q", m)
	}
}

func TestErrorCommentSaysThePlanWasNotJudged(t *testing.T) {
	body := Render(Input{Key: "envs/prod/tfplan", Workspace: "default", Err: "plan JSON: not a plan", Commit: "5948de7aa11bb22cc33dd44", Version: "v0.0.0"})
	mustContain(t, body, Marker("envs/prod/tfplan", "default"), "### applygate plan check: ❌ error", "could not judge this plan", "- `plan JSON: not a plan`", "judged at `5948de7aa11b`")
	for _, no := range []string{"allow", "tier"} {
		if strings.Contains(body, no) {
			t.Errorf("an error comment says %q:\n%s", no, body)
		}
	}
	if body := Render(Input{Key: "k", Err: "e", Commit: "not-a-commit`"}); strings.Contains(body, "judged at") {
		t.Errorf("a value that is not a commit is shown as one:\n%s", body)
	}
}

// A destroy or replace is a reason by itself; the resources the stateful
// reason already names are counted, not listed twice.
func TestDestroyReasonListsOnlyWhatIsNotNamedAbove(t *testing.T) {
	in := judge(t, plan(t, []change{
		{"aws_db_instance.main", "aws_db_instance", []string{"delete", "create"}},
		{"aws_instance.web", "aws_instance", []string{"delete"}},
		{"aws_instance.worker[0]", "aws_instance", []string{"create", "delete"}},
	}), config.Protected)
	body := Render(in)
	mustContain(t, body,
		"  - `aws_db_instance.main (aws_db_instance) is replaced`",
		"- A protected tier blocks any destroy or replace; this plan has 3 (1 named above)\n  - `aws_instance.web is destroyed`\n  - `aws_instance.worker[0] is replaced`\n",
	)
	if strings.Count(body, "aws_db_instance.main") != 1 || strings.Contains(body, "<details>") {
		t.Errorf("a resource is listed twice, or a short comment has a collapsed block:\n%s", body)
	}
	// Stateless only: the destroy is the whole reason.
	in = judge(t, plan(t, []change{{"aws_instance.web", "aws_instance", []string{"delete"}}}), config.Standard)
	mustContain(t, Render(in), "⚠️ ask", "- A standard tier asks about any destroy or replace; this plan has 1\n  - `aws_instance.web is destroyed`\n")
}
