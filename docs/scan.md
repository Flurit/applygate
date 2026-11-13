# Scan: what applygate would have decided

`applygate scan` reads the sessions Claude Code and Codex already recorded on this machine and reports what applygate would decide on each tool call in them. It needs no hook and no config, so it is a way to see applygate on your own commands before installing anything.

```bash
applygate scan                 # the last 30 days
applygate scan --days 0        # every session the agents kept
applygate scan --dir ~/infra   # only calls made in this directory or under it
applygate scan --all           # list every call it would block or ask about
applygate scan --json          # one JSON object per judged call
```

## What the report shows

- **Infrastructure commands:** how many it would block, ask about and allow, with the latest of each listed: the date, the agent, the directory, the command and the reason. The same command in the same directory is one entry with a count.
- **Changes to agent settings and applygate's own files:** calls that write a guard file, such as `.claude/settings.json` or `.applygate.yaml`.
- **Other shell commands:** the share it would ask about although they name no infrastructure tool, and what kept them from being plain commands (a loop, a script, a program it has no option list for). These asks come from directories that count as protected; the report says how many ran where no trusted `.applygate.yaml` covers the directory.
- **By repository:** calls, blocks, asks and whether a trusted config covers the repository, so you can see where a config would change the most.

## How a call is judged

Each recorded call is rebuilt as the hook input its agent would have sent and passed through the same code as a live hook call, with today's rules, today's user config and today's repository configs. The report gives the policy's verdict, not what your current mode would enforce, so observe mode does not hide anything.

- **Nothing is run.** The commands are read, not executed. Saved plans are not read either, because reading one starts the provider plugins of its directory.
- **Nothing leaves the machine.** The model judge, the live identity check and the live state check are not asked, whatever the config says.
- **Nothing is written.** The decision log, the approvals store and the judge cache are not touched.
- **Secrets are redacted** in every command the report or `--json` prints, as in the decision log. `--json` prints the commands of all judged calls, so treat its output like the session files themselves.

## What it reads

| Agent | Files | Calls read |
|---|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` (`CLAUDE_CONFIG_DIR` moves it), subagent sessions included | every tool call, with the directory the shell was in |
| Codex | `~/.codex/sessions/**/*.jsonl` (`CODEX_HOME` moves it) | commands, file changes and MCP calls, as Codex recorded them completed |

A call that appears in two session files, as after a resumed session, is counted once.

## Limits

- **Today's files, not the files of the day.** A verdict reads the directory: its config, its Terraform files, its git state, the scripts a command sources. Where those changed since, the call is judged as things are now. A script that has been deleted cannot be read, which makes an ask where there may have been none.
- **A directory that no longer exists** (a removed work tree, a temporary directory) cannot be judged. Those calls are counted and left out.
- **Applying a saved plan** is counted apart: the verdict depends on what the plan held, and a past plan is not kept.
- **Codex commands are judged as its hook sees them.** Codex runs a command in the directory the model chose but tells the hook only the session's directory ([limits.md](limits.md), "Codex working directory"), so a Codex command is judged at the most protected tier under the session root, as it would be live. The report shows the directory the command ran in.
- **Codex session formats.** The reader was checked against sessions written by Codex 0.162 to 0.166. Most hold a record of every completed command. Some `codex exec` sessions hold only the model's tool calls written as JavaScript; there a command is read when it is a plain string (`tools.exec_command({cmd:"..."})`) and left out when it is built at run time, and file edits are not read. Versions that recorded commands as model function calls are read from that format's shape and a test fixture, not from real sessions.
- **Compressed archives** (`~/.codex/archived_sessions/*.jsonl.zst`) are not read; the report says how many there are.
- **Other agents** (Cursor, Copilot CLI, Gemini CLI and the rest) are not read.
- **Tool calls the hook may never see.** A session file records every tool the model called. Whether the agent sends each of them to its PreToolUse hook is the agent's business; a tool it handles internally is still judged here.
- **The environment is the one scan runs in.** Variables that select a target, such as `AWS_PROFILE`, are taken from the shell you run `applygate scan` in, not from the session.
- **Time.** A verdict costs about 15 ms and a month of heavy use holds thousands of calls; they are judged in parallel, and a repeated call is judged once. On a machine with 15,000 calls in the window a scan took about a minute and a half.
