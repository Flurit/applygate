# Threat model

## Defends against

A **mistaken or manipulated agent** running with the developer's privileges. For example, an agent that:

- runs `terraform destroy`, `apply -auto-approve`, state surgery or cloud CLI deletes against the wrong or a protected environment;
- applies a saved plan in a different workspace from the one it was made in, or with a production profile set in the environment;
- works next to stale or archived state, or after the backend or lock file changed;
- hides a destructive command behind variables, `eval`, `bash -c`, here-documents, base64, Makefiles or scripts. This is often because injected instructions told it to;
- tries to turn off its own guardrails: skip-permissions flags, edits to hook settings, seatbelt's config or its log;
- reads cloud credential files.

## Does not defend against

- A malicious insider, or an attacker with the developer's shell outside the agent.
- An agent that reaches cloud credentials by a path the hook does not see (see [limits](limits.md)).
- Compromise of the seatbelt binary, the agent, or the toolchain.

## Self-protection

- Agent edits to `.claude/settings*.json`, managed settings, `.codex/hooks.json` and `config.toml`, `.cursor/hooks.json`, `.seatbelt.yaml`, the user config and the decision log are blocked in every tier and mode except observe. This covers the Write and Edit tools, `apply_patch`, shell redirection, and writers such as `rm`, `mv`, `cp`, `tee`, `sed -i` and `dd`.
- A repository config cannot move the log or turn on network access. Only the user-level config can.
- For organizations, deploy the hook through managed settings so neither developers nor agents can remove it. Claude Code supports managed-only hooks.

## Recommended pairing

Plan-only credentials for the agent. Apply credentials only for a human or a CI runner. An isolated runner for anything protected.
