# Scan: how exposed your infrastructure is to your agents

`applygate scan` answers two questions about this machine. What can a coding agent that runs here reach: is anything between it and production besides the hook? And what did the agents do: it reads the sessions Claude Code and Codex already recorded and reports what applygate would decide on each tool call in them. It needs no hook and no config, so it is a way to see both on your own machine before installing anything.

```bash
applygate scan                 # the last 30 days
applygate scan --boundary      # also ask the cloud what the credentials here can do (read-only)
applygate scan --days 0        # every session the agents kept
applygate scan --dir ~/infra   # only calls made in this directory or under it
applygate scan --all           # list every call it would block or ask about
applygate scan --share         # counts only, to send to someone else
applygate scan --json          # one JSON object per judged call
```

## What your agents can reach

The report opens with the boundary around the agent, because that is what holds when a verdict is wrong or a call never passes the hook ([boundary.md](boundary.md)). It makes the checks `applygate doctor --boundary` makes and gives the assurance level, L0 to L3.

Without `--boundary` it makes only the checks that read this machine: whether the install is managed, which credential files an agent that runs as you can read, and whether a host sandbox is set. It contacts nothing, so it cannot say what those credentials can do, and the level it gives is the level as far as the machine shows.

With `--boundary` it also runs the credential audit of `doctor --creds` ([credentials.md](credentials.md)): it asks AWS, Google Cloud, Azure and the clusters, read-only and with the credentials it audits, whether each one can change production without a person. The report then says one of three things:

- **A credential can change production without a person.** That is what a wrong verdict would reach; [credentials.md](credentials.md) shows how to close it.
- **None of the audited credentials can.** If those are all your agents can use, you do not need the hook to protect production. The part of applygate that fits such a setup is the plan check in the pipeline ([ci.md](ci.md)).
- **Some could not be checked, or match no environment.** A credential whose sign-in has expired, or that lacks a permission the audit needs, is not checked: the report says to sign in and run it again. A credential that can make destructive changes in an environment no config names cannot be called production or not: the report says to name your environments. Either way the audit does not show that production is out of reach.

Every audited credential is listed, the harmless ones too, with the identity the cloud returned for it.

The section ends with how many commands that change infrastructure (an apply, a destroy, a state change, a cloud write) the agents issued in the sessions read, and how many of those aimed at an environment that is protected or that no config names. Issued is what the session records; whether a command succeeded is not known.

## What it would have decided

- **Infrastructure commands:** how many it would block, ask about and allow, with the latest of each listed: the date, the agent, the directory, the command and the reason. The same command in the same directory is one entry with a count.
- **Changes to agent settings and applygate's own files:** calls that write a guard file, such as `.claude/settings.json` or `.applygate.yaml`.
- **Other shell commands:** the share it would ask about although they name no infrastructure tool, and what kept them from being plain commands (a loop, a script, a program it has no option list for). These asks come from directories that count as protected; the report says how many ran where no trusted `.applygate.yaml` covers the directory.
- **By repository:** calls, blocks, asks and whether a trusted config covers the repository, so you can see where a config would change the most.

## How a call is judged

Each recorded call is rebuilt as the hook input its agent would have sent and passed through the same code as a live hook call, with today's rules, today's user config and today's repository configs. The report gives the policy's verdict, not what your current mode would enforce, so observe mode does not hide anything.

- **Nothing is run.** The commands are read, not executed. Saved plans are not read either, because reading one starts the provider plugins of its directory.
- **Nothing leaves the machine** unless you pass `--boundary`. The model judge, the live identity check and the live state check are not asked, whatever the config says. `--boundary` contacts the cloud and the clusters for the credential audit and for nothing else; no recorded command, path or session content is sent.
- **Nothing is written.** The decision log, the approvals store and the judge cache are not touched.
- **Secrets are redacted** in every command the report or `--json` prints, as in the decision log. `--json` prints the commands of all judged calls, so treat its output like the session files themselves.

## A summary you can send

`applygate scan --share` prints the counts of a scan and nothing else: sessions, calls, how many infrastructure commands would be blocked, asked about and allowed, the share of other shell commands asked about, and the boundary level with the number of checks in each state. It holds no command, path, repository, account or program name. The reasons for asks are put in a fixed set of kinds ("a program with no option list", "shell syntax beyond a plain command") instead of being quoted, because a reason can name a program or a file.

It is meant for telling someone outside your organization, such as the applygate maintainers, how often applygate would get in your way, without showing them your work. It is printed to your terminal; applygate sends it nowhere.

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
- **The boundary is this machine's, today.** The checks read the user config and the working directory `scan` runs in, like `doctor --boundary`, and say nothing about the machine a past session ran on. `--dir` does not narrow them.
- **The credential audit has the limits of `doctor --boundary`** ([boundary.md](boundary.md), "What the check does and does not cover"): the Google Cloud and Azure audits are tested with stubs only, a credential in no environment the config names counts as unclear, and an MCP server with its own credentials is not seen.
- **Other agents** (Cursor, Copilot CLI, Gemini CLI and the rest) are not read.
- **Tool calls the hook may never see.** A session file records every tool the model called. Whether the agent sends each of them to its PreToolUse hook is the agent's business; a tool it handles internally is still judged here.
- **The environment is the one scan runs in.** Variables that select a target, such as `AWS_PROFILE`, are taken from the shell you run `applygate scan` in, not from the session.
- **Time.** A verdict costs about 15 ms and a month of heavy use holds thousands of calls; they are judged in parallel, and a repeated call is judged once. On a machine with 15,000 calls in the window a scan took about a minute and a half.
