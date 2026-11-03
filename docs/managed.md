# Managed install

Without a managed install, applygate's files belong to the user the agent runs as. The hook blocks the routes it sees, but an agent with that user's shell can, in the end, change anything that user can change. A managed install moves the guard out of the agent's reach: root owns every part of it, so the agent's user cannot change it at all.

```sh
sudo applygate install --managed            # Claude Code managed hooks next to the user's own
sudo applygate install --managed --exclusive  # only managed hooks run in Claude Code
sudo applygate trust                         # in each repository, after reviewing its .applygate.yaml
applygate doctor                             # check the install
```

It is supported on macOS and Linux. Windows is not supported yet, because applygate does not check file ownership there.

## What it installs

| Part | Path | What it does |
|---|---|---|
| Binary | `/usr/local/libexec/applygate/applygate` | a root-owned copy of the binary that ran the install; the managed hooks run it |
| System config | `/etc/applygate/config.yaml` | read after the user config, so what it sets wins. The install writes `mode: enforce` and `approvals: false`, and keeps a file that is already there |
| Trust store | `/etc/applygate/trusted.json` | the repository configs a person trusted with `sudo applygate trust`. Under a managed install it is the only store that counts |
| Claude Code | `managed-settings.d/applygate.json` in `/Library/Application Support/ClaudeCode/` (macOS) or `/etc/claude-code/` (Linux) | the `PreToolUse` hook with matcher `*` and `onFailure: block`, `permissions.disableBypassPermissionsMode: "disable"`, and with `--exclusive` `allowManagedHooksOnly: true` |
| Codex | `/etc/codex/requirements.toml` | not written: the install prints a snippet to add, since that file is the organisation's policy |

**Where these come from:**
- **Claude Code:** the managed settings keys and directories are from the Claude Code docs, read 2026-11-03. The docs say user, project and `--settings` values cannot override a managed key, and only a managed `disableAllHooks` turns managed hooks off. This is not tested live yet. Whether `claude --bare` or `CLAUDE_CODE_SIMPLE` skip managed hooks is not documented; the hook blocks an agent that starts a nested session that way.
- **Codex:** the `requirements.toml` keys are from the Codex docs, read 2026-11-03, partly as a summary. The printed snippet is not tested live; check it against the Codex docs before deploying it.

## What changes for the person

- **Repository configs need trusting again,** with `sudo applygate trust` in each repository. Configs trusted before the install are not carried over, because the user's store is one the agent's user could have written.
- **Every change to a repository config** needs `sudo applygate trust` before it takes effect. Until then every directory it covers is protected.
- **The system config** is edited with `sudo`. A system config that root does not own, or that others can write, is not read, and every directory is protected until it is fixed; `doctor` says why.
- **Upgrading:** run `sudo applygate install --managed` from the new binary. It replaces the managed binary and keeps the system config and trust store.

## Removing it

```sh
sudo applygate uninstall --managed           # removes the binary and the Claude Code drop-in file
sudo applygate uninstall --managed --purge   # also removes /etc/applygate
```

Without `--purge`, `/etc/applygate` stays, and repository configs are still judged by its trust store. Remove applygate's hook from Codex's `requirements.toml` yourself.

## What it does not cover

- **A user with `sudo`.** If the agent's user can run `sudo` without a password, the agent can too. The hook blocks commands that name the managed files, `sudo` ones included, but that check is the same default-deny the unmanaged install relies on. Give agents a user that cannot `sudo`, or one whose `sudo` asks for a password.
- **Hosts other than Claude Code and Codex.** Their hooks stay in user files.
- **The user-level install keeps running** next to the managed hook unless `--exclusive` is used, so a call may be judged twice. That costs time, not protection.
