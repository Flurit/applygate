# Threat model

## Defends against

A **mistaken or manipulated agent** running with the developer's privileges. For example, an agent that:

- runs `terraform destroy`, `apply -auto-approve`, state surgery or cloud CLI deletes against the wrong or a protected environment;
- applies a saved plan in a different workspace from the one it was made in, or with a production profile set in the environment;
- works next to stale or archived state, or after the backend or lock file changed;
- hides a destructive command behind variables, `eval`, `bash -c`, here-documents, base64, Makefiles or scripts. This is often because injected instructions told it to;
- tries to turn off its own guardrails: skip-permissions flags, edits to hook settings, applygate's config or its log;
- reads cloud credential files.

## Does not defend against

- A malicious insider, or an attacker with the developer's shell outside the agent.
- An agent that reaches cloud credentials by a path the hook does not see (see [limits](limits.md)).
- Compromise of the applygate binary, the agent, or the toolchain.

## Self-protection

- Agent edits to `.claude/settings*.json`, managed settings, `.codex/hooks.json` and `config.toml`, `.cursor/hooks.json`, `.applygate.yaml`, the user config and the decision log are blocked in every tier and mode except observe. This covers the Write and Edit tools, `apply_patch`, shell redirection, and writers such as `rm`, `mv`, `cp`, `tee`, `sed -i` and `dd`.
- A repository config cannot move the log or turn on network access. Only the user-level config can.
- Telemetry is off by default and carries only anonymous verdict counts ([telemetry.md](telemetry.md)). Its settings file is a guard path, `applygate telemetry on|off` run by an agent is blocked as guard tampering in every tier, and `APPLYGATE_TELEMETRY=0` or `DO_NOT_TRACK=1` in the environment forces it off whatever the file says.
- For organizations, deploy the hook through managed settings so neither developers nor agents can remove it. Claude Code supports managed-only hooks. `applygate init` installs at user scope (`~/.claude/settings.json`, `~/.codex/hooks.json`) so the hook fires whichever directory the session starts in; that closes the launch-directory trap for one developer but is still a file the developer owns. Managed settings remain the organisation-grade answer; the hook command there must be an absolute path to a binary the developer cannot replace.
- When a host does not report the directory a command runs in (Codex 0.165.0), applygate judges the command at the most protected tier it could be in under the session root rather than trusting the root's tier ([limits.md](limits.md), [hosts.md](hosts.md)).

## Recommended pairing

Plan-only credentials for the agent. Apply credentials only for a human or a CI runner. An isolated runner for anything protected.
