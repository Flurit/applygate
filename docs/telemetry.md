# Telemetry

applygate sends nothing unless a person turns telemetry on. Off is the default, off is what `init` leaves you with, and off is what every release ships with. This page says exactly what changes when you turn it on.

## What is sent

One JSON report, schema 1:

```json
{
  "schema": 1,
  "sent_at": "2026-10-30T09:00:00Z",
  "applygate": "0.3.0",
  "os": "linux",
  "arch": "amd64",
  "from": "2026-10-29T07:49:52Z",
  "to": "2026-10-30T08:58:11Z",
  "decisions": 169,
  "errors": 0,
  "counts": [
    {"version": "0.3.0", "agent": "claude", "mode": "observe", "verdict": "allow", "n": 92},
    {"version": "0.3.0", "agent": "claude", "mode": "observe", "verdict": "ask", "n": 5},
    {"version": "0.3.0", "agent": "codex", "mode": "observe", "verdict": "allow", "n": 68}
  ]
}
```

That is the whole list: the applygate version, operating system and architecture, the period the report covers, the number of decisions and of internal errors, and one count per (version, agent, mode, verdict). `agent` is the hook host (`claude`, `codex`) or `human` for `applygate apply`.

Not sent, ever: commands, paths, repository or directory names, workspace or backend names, AWS profiles or accounts, plan contents, findings, host names, user names, IP-derived data on our side beyond what any HTTP request carries, and no install id, machine id or session id. There is nothing in a report that ties it to the previous one.

The report is built from your local decision log at send time, so `applygate telemetry status --payload` prints exactly what the next report contains. The decision log itself never leaves the machine.

## When

- At most once every 24 hours, from the hook, after it has written its verdict. The send is bounded to 3 seconds and cannot change or delay the verdict; if it fails, the decisions stay pending and the next day's attempt covers them.
- Whenever you run `applygate telemetry send`.

## Switching it

```bash
applygate telemetry status            # on or off, why, endpoint, what the next report holds
applygate telemetry status --payload  # the next report as JSON
applygate telemetry on                # needs an endpoint: this build's default, or --endpoint https://...
applygate telemetry off
applygate telemetry send [--dry-run]
```

Settings and send state live in one file, `~/.config/applygate/telemetry.json` (or under `$XDG_CONFIG_HOME`). It is a guard path: an agent may not edit it, and an agent that runs `applygate telemetry on` or `off` is blocked as guard tampering in every tier. Only a person at a terminal flips the switch.

The environment can force it off regardless of the file, which is the setting for CI runners and shared machines:

```bash
export APPLYGATE_TELEMETRY=0   # or off, false, no
export DO_NOT_TRACK=1          # the cross-tool convention is honoured too
```

## Where it goes

A release build may carry a default endpoint, set at link time (`-X github.com/Flurit/applygate/internal/telemetry.DefaultEndpoint=https://…`). As of v0.3.1 no release carries one, so `applygate telemetry on` needs `--endpoint`. The endpoint must be `https`; plain `http` is accepted only on localhost, for a collector you run yourself. `APPLYGATE_TELEMETRY_ENDPOINT` in the environment overrides both, for teams that want the counts in their own store. Redirects are not followed, so a report never goes anywhere but the configured address.

The collector side is one `POST` of the JSON above; any endpoint that returns 2xx works. There is no authentication because there is nothing to authenticate: the payload identifies no one.

## Why it exists

The planning document (2026-10-29) asked for a way to know whether the gate is used and which verdicts it gives across hosts and versions, without weakening the project's "stays local" promise. Counts per version, agent, mode and verdict answer that. Nothing more was added, and the schema version is there so a change to the list is visible in the report itself.
