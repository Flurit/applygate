package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Flurit/applygate/internal/config"
	"github.com/Flurit/applygate/internal/decisionlog"
	"github.com/Flurit/applygate/internal/hook"
	"github.com/Flurit/applygate/internal/telemetry"
)

const telemetryUsage = `applygate telemetry status [--payload] [--log FILE]   is it on, where it sends, what the next report holds
applygate telemetry on [--endpoint URL]              turn it on (an https endpoint; this build's default when it has one)
applygate telemetry off                              turn it off (the file and its history stay)
applygate telemetry send [--dry-run] [--log FILE]    send now, or print what would be sent

What is sent: the applygate version, OS and architecture, the period covered, and
decision counts per (version, agent, mode, verdict), plus the count of internal
errors. No commands, paths, names or identifiers. Sent at most once a day.
APPLYGATE_TELEMETRY=0 or DO_NOT_TRACK=1 in the environment forces it off.
`

func cmdTelemetry(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		io.WriteString(stderr, telemetryUsage)
		return 2
	}
	fs := flag.NewFlagSet("telemetry "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	logPath := fs.String("log", "", "decision log (default: from config)")
	endpoint := fs.String("endpoint", "", "where reports go (https; http only on localhost)")
	dryRun := fs.Bool("dry-run", false, "print the report instead of sending it")
	payload := fs.Bool("payload", false, "print the next report as JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	env := hook.EnvMap()
	switch args[0] {
	case "status":
		return telemetryStatus(resolveLog(*logPath), env, *payload, stdout)
	case "on":
		s, err := telemetry.TurnOn(*endpoint)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		st := telemetry.Effective(env)
		fmt.Fprintf(stdout, "telemetry on, written to %s\n", telemetry.Path())
		fmt.Fprintf(stdout, "reports go to %s at most once a day: version, OS, architecture, decision counts per agent, mode and verdict, error count. Nothing else.\n", st.Endpoint)
		if !st.On {
			fmt.Fprintf(stdout, "note: nothing will be sent right now because it is %s\n", st.Reason)
		}
		fmt.Fprintln(stdout, "see the exact next report with: applygate telemetry status --payload; turn it off with: applygate telemetry off")
		_ = s
		return 0
	case "off":
		if _, err := telemetry.TurnOff(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "telemetry off (%s)\n", telemetry.Path())
		return 0
	case "send":
		ctx, cancel := context.WithTimeout(context.Background(), telemetry.SendTimeout)
		defer cancel()
		res, err := telemetry.Flush(ctx, resolveLog(*logPath), hook.Version, env, *dryRun)
		if err != nil {
			fmt.Fprintf(stderr, "telemetry: send failed: %v\n", err)
			return 1
		}
		if *dryRun {
			return writeJSON(stdout, res.Payload)
		}
		if !res.Sent {
			fmt.Fprintf(stdout, "nothing sent: %s\n", res.Reason)
			return 0
		}
		fmt.Fprintf(stdout, "sent %d decisions (%s to %s) to %s\n", res.Payload.Decisions, res.Payload.From.UTC().Format(time.RFC3339), res.Payload.To.UTC().Format(time.RFC3339), telemetry.Effective(env).Endpoint)
		return 0
	}
	fmt.Fprintf(stderr, "unknown telemetry command %q\n\n%s", args[0], telemetryUsage)
	return 2
}

func telemetryStatus(logPath string, env map[string]string, showPayload bool, stdout io.Writer) int {
	st := telemetry.Effective(env)
	state := "off"
	if st.On {
		state = "on"
	}
	fmt.Fprintf(stdout, "telemetry: %s\n", state)
	if !st.On {
		fmt.Fprintf(stdout, "  why: %s\n", st.Reason)
	}
	if st.Enabled {
		fmt.Fprintf(stdout, "  enabled since: %s\n", stamp(st.EnabledAt))
	}
	if st.Endpoint != "" {
		fmt.Fprintf(stdout, "  endpoint: %s\n", st.Endpoint)
	}
	fmt.Fprintf(stdout, "  settings: %s\n", telemetry.Path())
	fmt.Fprintf(stdout, "  reports sent: %d, last sent: %s, last attempt: %s\n", st.ReportsSent, stamp(st.LastSent), stamp(st.LastAttempt))
	if st.LastError != "" {
		fmt.Fprintf(stdout, "  last error: %s\n", st.LastError)
	}
	var entries []decisionlog.Entry
	if f, err := os.Open(logPath); err == nil {
		entries, _ = decisionlog.Read(f)
		f.Close()
	}
	p := telemetry.Pending(entries, st.LastSent, hook.Version)
	fmt.Fprintf(stdout, "  next report: %d decisions from %s, %d internal errors, %d count rows\n", p.Decisions, logPath, p.Errors, len(p.Counts))
	if showPayload {
		return writeJSON(stdout, p)
	}
	return 0
}

func resolveLog(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if cfg, err := config.Load(config.UserPath(), ""); err == nil && cfg.LogPath != "" {
		return cfg.LogPath
	}
	return config.DefaultLogPath()
}

func writeJSON(w io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return 1
	}
	w.Write(append(b, '\n'))
	return 0
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}
