# Limits

seatbelt reduces the chance that a mistaken or manipulated agent damages infrastructure. It cannot guarantee that it won't. Use it together with plan-only credentials and an isolated runner.

## What it cannot see

- **Paths around the hook.** If the agent can reach cloud credentials and run code by any route the hook does not inspect, seatbelt does not see it. Examples: an MCP server with its own credentials, a tool the matcher does not cover, or a process started earlier in the background.
- **Code in other languages.** `python -c`, `node -e` and scripts with non-shell shebangs are not analyzed. If such code mentions terraform, tofu, kubectl, aws operations or guard files, seatbelt treats it as dynamic (ask) or as tampering. If it mentions none of them, it passes.
- **Runtime values.** Environment variables seatbelt cannot see, files written earlier in the same command, `read` from stdin, and command substitutions other than echo/printf/cat/base64/xxd/rev/which/dirname are unresolved. In a command position they cause an ask. As plain arguments to non-infrastructure programs they do not.
- **Aliases and functions from the user's shell profile.** Only aliases defined in the same command or in config (`aliases:`, default `tf: terraform`) are expanded.
- **Remote and container contexts.** `ssh host '…'` is analyzed with an unknown directory, which is protected in strict mode. `docker run … hashicorp/terraform …` is unwrapped only when the image name contains terraform, tofu or terragrunt.
- **`make`** variables are expanded only when the Makefile defines them literally. Includes, pattern rules and functions are not followed.
- **Backend blocks** are read with a small parser that only understands literal string attributes. Partial configuration (`-backend-config`) is visible only through the `.terraform` cache.

## Plan gate

- seatbelt never runs `plan`. For `apply <planfile>` it runs `<engine> show -json <planfile>` (read-only; it starts provider plugins to load schemas). If that fails, the plan counts as unreadable: a critical finding, so protected tiers block. Set `plan_gate.run_show: false` to skip running show. Applying saved plans in protected tiers is then blocked.
- The rules are AWS-first. GCP and Azure resources are counted for destroy and replace, but their stateful types and protections are not known.
- The workspace check reads the workspace that Terraform 1.x and OpenTofu record in the planfile (protobuf field 13 → 3). This was verified on a Terraform 1.16.1 planfile only.

## Agents

- **Claude Code:** only `dontAsk` turns a hook "ask" into a block. In `bypassPermissions` Claude Code still shows the ask prompt — this was observed live on Claude Code 2.1.312 (test T3.2), but it is **not documented**, so the behavior could change. Rerun T3.2 (`review/manual_agent_tests.md`) on each new Claude Code version; if a future version silently allows an "ask" under `bypassPermissions`, restore the ask→block conversion for that mode.
- **Codex:** does not support "ask" (it fails the hook and runs the tool), so every ask becomes a block. Codex hooks need to be trusted with `/hooks` before they run.
- Hook crashes and agent-side timeouts: see the README section "What happens when seatbelt fails".

## Not in v1

Backup isolation checks, plan-hash approval, CI mode, receipts, GCP/Azure/Kubernetes/Pulumi rules, and live state lineage comparison. The only network call is the optional STS identity check (`preflight.live_identity`), which only the user config can enable.
