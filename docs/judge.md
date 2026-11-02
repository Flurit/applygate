# Model judge (opt-in)

applygate's rules decide every call they recognize: Terraform and its relatives, the aws, gcloud and az CLIs, kubectl and helm, guard files, and the known infrastructure MCP tools. Everything else is allowed. That includes Pulumi, CDK, PaaS CLIs, database clients, object-storage tools, inline SDK code, wrapper scripts and unknown MCP tools.

The model judge is an optional second look at those calls. When the user turns it on, applygate sends a call the rules let through without recognizing anything to a language model. The model answers allow, ask or block, and the call gets the stricter of the rule verdict and the model's.

- **Escalate only.** The judge can add a prompt or a block, never remove one. A call the rules stop stays stopped whatever the model says, and an error, a timeout or an answer the model was talked into by text inside the call leaves the rule decision as it is.
- **Off by default, user config only.** The call leaves the machine, so only the user config can turn the judge on or configure it. A repository config can turn it off (`judge: {enabled: false}`) and nothing else.
- **Your own key or your own program.** applygate talks to any OpenAI-compatible endpoint with a key from your environment, or runs a program you name. It ships no model, no key and no account.

## What is sent, and when

A call reaches the judge only when all of these hold:

1. The rules allowed it without recognizing any action in it. Anything they classified, safe or not, is decided by the rules alone.
2. It is one of:
   - a **shell command** that starts a program outside a short list of local ones;
   - a **file write or edit**, whatever the file;
   - an **MCP call** to a tool that the [known-tool table](mcp.md) does not cover and `skip_mcp` does not exclude.

   File reads never go. The local list covers reading and searching files, building, testing and linting, package installs, local git (a push only without force or delete), and file commands that stay inside the working tree. Some calls go even though they look local:
- `env` printing the environment;
- a local command that names a credential file or directory (`.env`, `*credentials*`, key files, `.netrc`, `~/.aws`, `~/.ssh`, `~/.kube`, gcloud);
- a command that changes a file outside the working tree;
- a command that contains anything the shell analyzer cannot resolve.

What the model receives:

- **The call itself:** the agent name and the tool name.
- **For shell commands:** the command.
- **For writes:** the file path and up to 4,000 characters of the content (for an edit, the text replaced and its replacement).
- **For MCP calls:** the arguments.
- **Where it runs:** the working directory, and the environment name and tier applygate resolved for it.

Secrets are redacted first, the same way as in the decision log: AWS keys, `password=`/`token=`/`secret=` values, `Authorization:` headers, GitHub and Slack tokens, private-key blocks. Redaction is pattern-based and can miss a secret in an unusual form.

## Turning it on

In the user config (`~/.config/applygate/config.yaml`; `applygate doctor` prints the path):

```yaml
judge:
  enabled: true
```

That uses the defaults:
- **Endpoint:** Anthropic's OpenAI-compatible endpoint, `https://api.anthropic.com/v1`.
- **Model:** `claude-haiku-5-5`.
- **Key:** read from `ANTHROPIC_API_KEY` in the hook's environment.
- **Timeout:** 10 seconds per call.

The key never goes in the config file.

### Other providers

Any endpoint that speaks OpenAI's chat completions API works. Set `base_url` and `model`, and `api_key_env` when the endpoint needs a key:

```yaml
judge:
  enabled: true
  base_url: https://api.openai.com/v1
  model: <a model id>
  api_key_env: OPENAI_API_KEY
```

Google's Gemini API, measured below. It is slower than the default, so give it a longer timeout:

```yaml
judge:
  enabled: true
  base_url: https://generativelanguage.googleapis.com/v1beta/openai
  model: gemini-3.8-flash
  api_key_env: GEMINI_API_KEY
  timeout: 20s
```

A local server needs no key:

```yaml
judge:
  enabled: true
  base_url: http://localhost:11434/v1   # for example Ollama
  model: <a local model>
```

How each endpoint is used:
- **Request:** the answer is asked for as a JSON schema (`response_format` with `strict: true`). An endpoint that ignores that still works when the model replies with the JSON object.
- **`reasoning_effort`:** sent only when you set it, for endpoints that accept it. The default endpoint accepts it and ignores it: low and high gave the same verdicts, latency and cost.
- **Testing:** the default endpoint and Gemini's were called live; see the measured results below. For other providers these settings are written from the providers' published API shape, and only the request format is tested (against a local test server).

### A program instead of an endpoint

```yaml
judge:
  enabled: true
  backend: command
  command: ["sh", "/path/to/examples/judge/claude-cli.sh"]
```

The contract:
- **Input:** one request as JSON on stdin, `{"system", "prompt", "schema", "call"}`.
- **Output:** `{"verdict": "allow"|"ask"|"block", "reason": "..."}` on stdout.
- **Anything else** counts as an error, which leaves the rule decision. That includes a non-zero exit, unreadable output or running past the timeout.

[`examples/judge/claude-cli.sh`](../examples/judge/claude-cli.sh) asks Claude through the `claude` CLI's own login, so it needs no API key. It was tested live through `applygate check`; see the measured results below.

Two scripts use decision models, which answer a multiple-choice question with a probability per option instead of writing text. Each sends the judge's instructions as one question with the options allow, ask and block, and takes the most likely option. These models give no explanation, so the reason shown lists the probabilities.
- **[`examples/judge/jev.sh`](../examples/judge/jev.sh):** TypeSafe AI's Jev (`jev-latest`), with a key in `TYPESAFE_API_KEY`. Measured below.
- **[`examples/judge/openai-decisions.sh`](../examples/judge/openai-decisions.sh):** OpenAI's Decisions API (`gpt-6-luna`), with a key in `OPENAI_API_KEY`. Measured below.

Both set `APPLYGATE_JUDGE_MODEL` to choose another model.

### All settings

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turn the judge on (user config); a repository config may only set `false`. |
| `backend` | `openai` | `openai` (any OpenAI-compatible endpoint) or `command`. |
| `base_url` | `https://api.anthropic.com/v1` | The endpoint. Setting it makes `model` required. |
| `model` | `claude-haiku-5-5` | The model id. |
| `api_key_env` | `ANTHROPIC_API_KEY` with the default endpoint, none otherwise | Environment variable holding the key. |
| `reasoning_effort` | not sent | Passed through as `reasoning_effort`. |
| `command` | none | Program and arguments for `backend: command`. |
| `timeout` | `10s` | Per call. The hook also ends the judge 3 seconds after its own decision deadline, so the Claude Code plugin's 30-second hook timeout is never reached. |
| `skip_mcp` | none | MCP tool name globs never sent, for tools you know only read, for example `["mcp__playwright__*"]`. |

## What the agent and the person see

An escalation reads like any other applygate verdict and names the model:

```
applygate: ASK.
- [ask] model-judge: the model judge (claude-haiku-5-5) says: This prints a production database password from secret/prod/db into the session transcript, which is credential access and needs confirmation. The rules do not recognize this call; the judge is a language model the user turned on for such calls, and it can be wrong.
  environment: prod (tier protected; the environment of the working directory)
```

- **Prompts and blocks:** asks become blocks on agents that cannot show a prompt, and observe mode allows and records, exactly as for rule verdicts.
- **Approvals:** a person can approve a judge's block once with `applygate approve`, like an ask. It is a model's opinion, not a rule. A rule's block still can never be approved.
- **The log:** every judge call is recorded in the decision log under `judge` (model, verdict, reason, time, whether it came from the cache, error).
- **The cache:** answers are cached for 24 hours in `judge-cache.json` next to the log, which is a guard path, so a repeated call does not pay the model again.
- **`applygate check`** runs the judge when it is on (`--no-judge` skips it), so you can try a command before an agent does.
- **`applygate doctor`** reports the judge's model, endpoint and timeout, or why it cannot be asked (for example a missing key), without calling the model.

## How well it works

All measurements are in [`experiments/model-judge`](../experiments/model-judge/RESULTS.md).

**How the judge was measured:**
- **Held-out sets:** five, each written by an independent red-team agent that never saw the prompt, the filter, the adapters or the earlier sets. Each set was committed before any model saw it.
- **The unbiased numbers come from the fifth set.**
  - The first four were seen while the prompt, the filter and the decision-model setup below were designed.
  - The fifth was scored once per judge, after every design choice was committed.
  - 7 of its 143 calls happen to repeat calls from earlier sets (common commands such as `docker system prune`). Leaving them out moves no judge by more than one call.

Fifth held-out set, this release's prompt and filter, one run per judge:

| Judge | Should be stopped: caught (72) | Should go through: escalated (71) | Model time p95 | Cost per judged call |
|---|---|---|---|---|
| Gemini 3.8 Flash, Gemini's OpenAI-compatible endpoint | 71 | 0 | 8.9 s | not measured |
| Claude Haiku 5.5, the default endpoint | 70 | 4 | 2.5 s | $0.00022 |
| Jev, [`jev.sh`](../examples/judge/jev.sh) | 69 | 5 | 0.65 s | about $0.00006 |
| OpenAI `gpt-6-luna`, [`openai-decisions.sh`](../examples/judge/openai-decisions.sh) | 65 | 3 (and 1 refusal) | 0.68 s | about $0.00011 |

- **The rules alone** catch none of the calls in these sets.
- **Every judge but Gemini missed** a GitHub issue comment carrying a hidden instruction to AI assistants, posted through an unknown MCP tool. Gemini's one miss was a file write. Haiku and Jev also allowed deleting one Grafana dashboard on a shared host, which applygate's own table allows in a standard tier.
- **Every judge but Gemini** wrongly escalated both `docker system prune -af --volumes` and an `octodns-sync` of the production DNS config, which the set labels as going through.
- **Gemini is the most accurate and the slowest:** model time about 5 s at the median and 9 to 10 s at p95. Some calls take longer than the default 10-second timeout, and a call that times out is left to the rules, so use `timeout: 20s`.
- **The decision models answer in under a second.** Jev comes within one or two calls of Haiku on this set. On the fourth set (seen) it was further behind: 61 to 62 caught against Haiku's 62 to 63 through the same endpoint, with 6 to 7 false escalations against 5.
- **One long question works as well as many short ones.** Asking the decision models nine yes/no questions and letting applygate's tier table decide, with thresholds tuned on the earlier sets, did not beat one question on the fifth set:
  - Jev: 67 caught, 2 escalated;
  - `gpt-6-luna`: 65 caught, 3 escalated.

  Those adapters stay in the experiment (`experiments/model-judge/decision-facts`).
- **Caveat:** the prompt was tuned on Claude models, and Claude agents wrote every set.

Earlier measurements on sets already seen:
- **Through the `claude` CLI:** Haiku 5.5 caught 66 of 67 on the fourth set, and 269 of 276 (97%) on all four with this release's filter, with 14 of 248 (6%) false escalations.
- **Through the default endpoint:** it caught 62 to 63 on the fourth set over three runs, missing three calls the CLI asked about; why the paths differ is not established. `reasoning_effort` is accepted and changes nothing measurable.
- **On real agent traffic** from a week of Terraform work, the judge escalated none of 162 calls; 11% of the shell calls reached it.

**Live in headless Claude Code 2.1.314 on macOS,** with both the default endpoint ([review/judge-live, 2026-11-02](../review/judge-live/2026-11-02-default-endpoint.md)) and the command backend ([2026-11-01](../review/judge-live/2026-11-01-claude-code.md)):
- `pulumi destroy` on a protected stack was blocked;
- `pulumi preview` was judged and allowed;
- printing a Vault password was asked about, and did not run;
- `ls` was not sent to the judge (command-backend run).

With the default endpoint the hook took 1.2 to 3.0 s per judged call, against 3.3 to 3.9 s with the command backend, which has to start the `claude` CLI. Gemini, Jev and `gpt-6-luna` were run through `applygate check`, not inside an agent.

**Not measured:**
- **Any provider or model other than those above.** Accuracy, false escalations and latency are unknown until measured. The experiment's runner (`experiments/model-judge/eval -backend openai -base-url … -api-key-env …`, or `-backend command`) scores any OpenAI-compatible endpoint or adapter on the same held-out sets.
- **The default endpoint's long-term support.** Anthropic describes it as "not considered a long-term or production-ready solution for most use cases".
- **Agents other than Claude Code, and an interactive session.** Codex, an interactive session's ask prompt, and `applygate approve` for a judge's block are covered by tests only.

## Limits

- **A model can be wrong.** It missed up to three calls of each held-out set, mostly writes whose effect depends on context it cannot see, and it can be fooled in ways the sets did not try. The rules stay the guarantee; the judge is extra coverage.
- **Some calls skip the judge.** The filter keeps local work away from the model: reads inside the working tree, builds, tests, local git. So a destructive call that looks like local work is not judged, for example `git log -p` printing a key from history.
- **Latency.** A judged call waits for the model. With Claude Haiku 5.5 that was 1.5 to 1.8 s at the median and 2.6 to 3.6 s at p95 in the measurements; with Gemini 3.8 Flash it was 5.1 s and 9.4 s; with Jev, 0.46 s and 0.56 s; with `gpt-6-luna`, 0.40 s and 0.74 s. A cached answer costs nothing.
- **A timeout means no judgement.** A call that runs past `timeout` is left to the rules, which allow it. Set the timeout above your endpoint's slowest answers; the judge's limit is 25 seconds, inside the plugin's 30-second hook limit.
- **Your data goes to the endpoint you configure.** Use a local server or a provider whose data terms you accept. Turn it off per repository with `judge: {enabled: false}`.
- **Workspace keys.** Anthropic's compatible endpoint needs an `anthropic-workspace-id` header for keys not scoped to a workspace, which applygate does not send. Use a workspace-scoped key.
