# Commands

`applygate help` lists them too; `applygate COMMAND -h` shows a command's options.

| Command | What it does |
|---|---|
| `applygate init` | Write a starter config and install hooks for the agents it finds |
| `applygate check "<cmd>"` | Dry-run a command (exit 0 allow, 4 ask, 3 block); `explain` shows the reasoning |
| `applygate apply <planfile>` | Judge a saved plan, confirm, then apply |
| `applygate trust` | Review and trust this repository's `.applygate.yaml`; until then it is not read and every directory is protected |
| `/usr/bin/sudo /path/to/applygate install --managed --exclusive` | Root-owned install the agent's user cannot change ([managed.md](managed.md)) |
| `applygate approve [ID]` | Allow once a call an agent was stopped on because it could not ask you; without ID, list pending requests |
| `applygate plan-check plan.json` | Judge `terraform show -json` output |
| `applygate scan [--days N] [--dir DIR] [--boundary] [--share]` | What your agents can reach (the boundary checks; `--boundary` adds the credential audit), and what applygate would decide on the calls Claude Code and Codex already made, read from their session files; no hook needed, nothing is run. `--share` prints counts only ([scan.md](scan.md)) |
| `applygate report` / `suggest` | Summarize the decision log / propose a config from it |
| `applygate doctor` | Check config, hooks and versions |
| `applygate doctor --boundary [--require L2]` | The assurance level this machine reaches (managed install, audited credentials, host sandbox), exit 1 below the level you require ([boundary.md](boundary.md)) |
| `applygate doctor --creds` | Ask AWS, Google Cloud, Azure and the clusters whether the credentials here can change production without a person ([credentials.md](credentials.md)) |
| `applygate hook install\|remove --agent NAME` | Manage one agent's hook |
| `applygate hosts` | What each agent supports |
| `applygate selftest` | Run the scenario pack against this binary |
| `applygate telemetry status\|on\|off` | Anonymous usage counts, off by default |
