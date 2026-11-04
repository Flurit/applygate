# Managed install

Without a managed install, applygate's files belong to the user the agent runs as. The hook blocks the routes it sees, but an agent with that user's shell can, in the end, change anything that user can change: that self-protection is best-effort. A managed install moves the guard out of the agent's reach: root owns every part of it, so the agent's user cannot change it at all. It is the only setup whose self-protection applygate documents as a guarantee ([threat-model.md](threat-model.md#self-protection)).

```sh
# Install from a release you verified (docs/install.md), by its full path:
/usr/bin/sudo /path/to/verified/applygate install --managed --exclusive  # only managed hooks run in Claude Code
/usr/bin/sudo /path/to/verified/applygate install --managed              # Claude Code managed hooks next to the user's own
# From then on, use the managed binary by its path:
/usr/bin/sudo /usr/local/libexec/applygate/applygate trust    # in each repository, after reviewing its .applygate.yaml
/usr/local/libexec/applygate/applygate doctor                 # check the install
```

**Why full paths:** `sudo` and `applygate` found on `PATH` may be programs the agent's user planted. The hook blocks the plants it sees, but a managed install should not depend on that. A planted `sudo` would be handed your password, and a planted `applygate` run as root could change the system config and trust store. So run `/usr/bin/sudo` with an absolute path to a binary root owns, or to a release you verified yourself. `applygate doctor` and the trust prompt print the commands that way.

**`--exclusive` is recommended.** Without it, Claude Code runs user, project and plugin hooks next to the managed one. Those are files the agent's user can write (the hook blocks the writes it sees, such as skills, subagents and commands whose frontmatter declares hooks). From Claude Code's docs, not tested live: hooks run in parallel, and one that returns `updatedInput` replaces the call's input after applygate allowed the original. `--exclusive` sets `allowManagedHooksOnly`, which turns the others off.

It is supported on macOS and Linux. Windows is not supported yet, because applygate does not check file ownership there.

## What it installs

| Part | Path | What it does |
|---|---|---|
| Binary | `/usr/local/libexec/applygate/applygate` | a root-owned copy of the binary that ran the install; the managed hooks run it |
| System config | `/etc/applygate/config.yaml` | read before the user config, which may then only tighten, like a repository config: loosening settings (`mode: observe`, `strict: false`, a looser `default_tier` or `on_error`, `aliases`, `wrappers`, `unknown_dir: session_root`, disposable or standard environments, the judge, `log_path`, the network checks) come from the system config only. The install writes `mode: enforce` and `approvals: false`, and keeps a file that is already there |
| Trust store | `/etc/applygate/trusted.json` | the repository configs a person trusted with the managed binary's `trust`. Under a managed install it is the only store that counts |
| Claude Code | `managed-settings.d/applygate.json` in `/Library/Application Support/ClaudeCode/` (macOS) or `/etc/claude-code/` (Linux) | the `PreToolUse` hook with matcher `*` and `onFailure: block`, `permissions.disableBypassPermissionsMode: "disable"`, and with `--exclusive` `allowManagedHooksOnly: true` |
| Codex | `/etc/codex/requirements.toml` | not written: the install prints a snippet to add, since that file is the organisation's policy |

**Where these come from:**
- **Claude Code:** the managed settings keys and directories are from the Claude Code docs, read 2026-11-03. The docs say user, project and `--settings` values cannot override a managed key, and only a managed `disableAllHooks` turns managed hooks off. This is not tested live yet. Whether `claude --bare` or `CLAUDE_CODE_SIMPLE` skip managed hooks is not documented; the hook blocks an agent that starts a nested session that way.
- **Codex:** the `requirements.toml` keys are from the Codex docs, read 2026-11-03, partly as a summary. The printed snippet is not tested live; check it against the Codex docs before deploying it.

## What changes for the person

- **Your user config may only tighten.** Settings in it that would loosen protection are ignored, and `applygate doctor` lists them; put them in `/etc/applygate/config.yaml` with `sudo` if you want them. This is what keeps the agent's user from loosening the guard through a file it owns.
- **Repository configs need trusting again,** with `/usr/bin/sudo /usr/local/libexec/applygate/applygate trust` in each repository. Configs trusted before the install are not carried over, because the user's store is one the agent's user could have written.
- **Every change to a repository config** needs the managed binary's `trust` again before it takes effect. Until then every directory it covers is protected.
- **The system config** is edited with `sudo`. A system config that root does not own, or that others can write, is not read, and every directory is protected until it is fixed; `doctor` says why.
- **The judge is the system config's.** A `judge:` section in your user config is ignored; one in the system config cannot be turned off from the user config.
  - A `command` judge must name its program by its full path, and the program and every script it is given must be root's alone, as engines are; otherwise every call the judge would see is asked about. It runs in `/` with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `HOME`, `TMPDIR`, `CURL_HOME` and `XDG_CONFIG_HOME` set to `/var/empty`, `PYTHONNOUSERSITE=1`, and from the agent's environment only `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ` and variables ending in `_API_KEY` or `_TOKEN`. So `BASH_ENV`, a planted `sh`, a `.curlrc`, a Python `usercustomize.py` or `.pth` file, a shell rc or Claude Code user settings in the agent's home cannot answer for it. `APPLYGATE_JUDGE_*` and the proxy variables are not passed: a script that takes its endpoint or model from them uses its default, and a judge that needs other settings takes them from a root-owned wrapper script.
  - An `openai` judge must use an `https://` `base_url`, and talks to it without a proxy.
  - The judge cache is not used: it lives in the agent's user's state directory.
  - A judge that fails (unreachable, timed out, an error) makes the call unjudgeable, which is an ask outside disposable environments, since the agent's user decides whether a local server or a proxy answers. `SSL_CERT_FILE` and `SSL_CERT_DIR` are cleared at hook start.
- **The plan gate runs a root-owned engine only.** To read a saved plan the hook runs `terraform show -json` (or `tofu`). Under a managed install that binary, after symlinks, and its directory must be owned and writable by root only; a Homebrew or `~/.local/bin` install is neither, so the saved plan is unverifiable until you name a root-owned copy in the system config:

  ```yaml
  plan_gate:
    engines:
      terraform: /usr/local/libexec/applygate/terraform
  ```

  `TG_TF_PATH` is held to the same rule, and so is the `aws` CLI that `preflight.live_identity` runs (`plan_gate.engines.aws`). `plan_gate.engines` in the user config is ignored under a managed install.
- **Upgrading:** run `/usr/bin/sudo /path/to/verified/applygate install --managed` with the new release, verified as in [install.md](install.md), by its full path. It replaces the managed binary and keeps the system config and trust store.

## Removing it

```sh
/usr/bin/sudo /usr/local/libexec/applygate/applygate uninstall --managed           # removes the binary and the Claude Code drop-in file
/usr/bin/sudo /usr/local/libexec/applygate/applygate uninstall --managed --purge   # also removes /etc/applygate
```

Without `--purge`, `/etc/applygate` stays: the system config keeps overriding your user config (which may then still only tighten), and repository configs are still judged by its trust store. Remove applygate's hook from Codex's `requirements.toml` yourself.

## What it does not cover

- **The state directory.** The decision log (`~/.local/state/applygate/`) belongs to the agent's user, so an agent that gets around the hook could rewrite it; treat it as a record, not evidence. Approvals live there too, which is why the install turns them off.

- **A user with `sudo`.** If the agent's user can run `sudo` without a password, the agent can too. The hook blocks commands that name the managed files, `sudo` ones included, but that check is the same default-deny the unmanaged install relies on. Give agents a user that cannot `sudo`, or one whose `sudo` asks for a password.
- **Hosts other than Claude Code and Codex.** Their hooks stay in user files.
- **Credentials.** The managed install keeps the hook out of the agent's reach; it does not change what the agent's credentials can do when a call the hook misjudged runs. Give the agent read-only production credentials and keep writes behind MFA ([credentials.md](credentials.md)); `applygate doctor --creds` checks it.
- **The agent CLI itself.** Claude Code and Codex read the managed settings, so a `claude` or `codex` the agent's user can replace (a native install in the home directory, a user-owned npm or Homebrew prefix) can be swapped for a wrapper that starts sessions without the hook, or for a release that ignores managed settings. The hook blocks the routes it sees (writes to the known install locations and the names on `PATH`, `claude update`, `npm i -g @anthropic-ai/claude-code`, `brew upgrade codex`), and `applygate doctor` reports an install your user can write. Install the agent CLIs root-owned (a system package, or an npm prefix root owns) for the guarantee to hold.
- **The user-level install keeps running** next to the managed hook unless `--exclusive` is used, so a call may be judged twice. That costs time, not protection.
