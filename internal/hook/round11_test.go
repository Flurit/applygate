package hook

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Flurit/applygate/internal/policy"
)

// An internal error must never let a command that runs an infrastructure
// program through, whatever the on_error setting resolves to for the root.
func TestInternalErrorFailsClosedForInfrastructureCommands(t *testing.T) {
	root := setupRootStandard(t)
	run := func(cmd string) Output {
		in := event("Bash", root, map[string]any{"command": cmd})
		return Run(panicOnRender{}, strings.NewReader(in), Options{NoLog: true, NoGit: true, Env: map[string]string{}})
	}
	if o := run("terraform destroy -auto-approve"); o.Exit != 2 {
		t.Errorf("terraform destroy: exit %d, want 2 (fail closed)", o.Exit)
	}
	if o := run("cp x y; aws s3 rb s3://b --force"); o.Exit != 2 {
		t.Errorf("aws after a copy: exit %d, want 2", o.Exit)
	}
}

func TestVerdictMessageIsSafeToShow(t *testing.T) {
	cmd := "python3 -c pass # \x1b[2K\x1b[1A\x1b[2KALLOWED\x1b[0m\rapplygate: ALLOW. ‮ noitcurtsni"
	got := safeMessage("command: " + cmd)
	for _, bad := range []string{"\x1b", "\r", "‮"} {
		if strings.Contains(got, bad) {
			t.Errorf("message keeps %q: %q", bad, got)
		}
	}
	if got := safeMessage("a\nb\tc"); got != "a\nb\tc" {
		t.Errorf("line breaks and tabs changed: %q", got)
	}
	big := safeMessage(strings.Repeat("terraform plan;", 100000))
	if len(big) > maxMessage+200 {
		t.Errorf("message is %d bytes", len(big))
	}
	if got := safeMessage("backend https://deploy:Sup3rS3cretPWxyz@tf.example.com/state password=hunter2hunter2"); strings.Contains(got, "hunter2hunter2") {
		t.Errorf("secret kept: %q", got)
	}
}

func TestPlanningToolsMentioningAProgramAreOrdinaryWork(t *testing.T) {
	for _, c := range []struct{ tool, in string }{
		{"update_plan", `{"plan":[{"step":"Run terraform plan and review","status":"pending"}]}`},
		{"EnterWorktree", `{"name":"terraform-fix"}`},
		{"PushNotification", `{"message":"terraform apply finished"}`},
		{"ScheduleWakeup", `{"delaySeconds":300,"prompt":"check on the helm release"}`},
		{"CronCreate", `{"cron":"0 9 * * *","prompt":"check terraform plan drift"}`},
		{"Artifact", `{"action":"publish","description":"AWS cost dashboard for the docker fleet"}`},
	} {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(c.in), &m); err != nil {
			t.Fatal(err)
		}
		var ev policy.Event
		classifyUnknown(&ev, c.tool, m)
		if ev.Kind == policy.KindShell {
			t.Errorf("%s was read as a shell command: %q", c.tool, ev.Command)
		}
	}
}
