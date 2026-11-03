# Model judge (opt-in)

**applygate does not need a model.**
- **The rules are deterministic.** They give the same verdict for the same input every time, explain every verdict, work offline, and cost nothing.
- **What they cover:** every call they recognize, which is Terraform and its relatives, the aws, gcloud and az CLIs, kubectl and helm, guard files, and the known infrastructure MCP tools.
- **Where most users stop:** for infrastructure managed through those tools, the rules are the whole product.

**What the rules let through.** Everything they do not recognize is allowed, including Pulumi, CDK, PaaS CLIs, database clients, object-storage tools, inline SDK code, wrapper scripts and unknown MCP tools. On the held-out sets below, the rules alone stop none of those calls.

**What the judge adds.** The model judge is an optional second look at exactly those calls. When you turn it on and choose a model, applygate sends a call the rules let through without recognizing anything to that model. The model answers allow, ask or block, and the call gets the stricter of the rule verdict and the model's.

- **Escalate only.** The judge can add a prompt or a block, never remove one. A call the rules stop stays stopped whatever the model says, and an answer the model was talked into by text inside the call leaves the rule decision as it is. So does a network error or a timeout. A call that keeps the judge from answering is different: one too large to send (over 16,000 bytes of command or MCP arguments), one the model refuses, or one whose answer holds no verdict is asked about in protected and standard environments, so a call cannot get past the judge by breaking it.
- **Off by default, no default model, user config only.** You choose the provider and model; applygate recommends none. The call leaves the machine, so only the user config can turn the judge on or configure it, and a repository config can only turn it off (`judge: {enabled: false}`).
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

## Choosing a judge

Every option below was measured the same way: on the fifth held-out set (143 calls the rules let through, written independently and scored once per judge), with applygate's prompt and the filter of that time. The filter now sends more calls to the judge (see Limits), which these numbers do not reflect; they have not been measured again. The full method is under [How well it works](#how-well-it-works).

| Option | Should be stopped: caught (72) | Should go through: escalated (71) | Model time p95 | Cost per judged call |
|---|---|---|---|---|
| No judge (the rules alone) | 0 | 0 | none | none |
| Claude Haiku 5.5, Anthropic's OpenAI-compatible endpoint | 70 | 4 | 2.5 s | $0.00022 |
| Claude through the `claude` CLI (`claude-cli.sh`) | not measured on this set (66 of 67 on the fourth) | 5 of 61 on the fourth | 3.3 to 3.9 s in the hook | your Claude plan |
| Gemini 3.8 Flash, Gemini's OpenAI-compatible endpoint | 71 | 0 | 8.9 s | not measured |
| Jev, a decision model (`jev.sh`) | 69 | 5 | 0.65 s | about $0.00006 |
| `gpt-6-luna`, OpenAI's Decisions API (`openai-decisions.sh`) | 65 | 3, and 1 refusal | 0.68 s | about $0.00011 |
| A local model, or any other provider | not measured | not measured | | |

A caveat applies to every row: the prompt was tuned on Claude models and Claude agents wrote every test set, which may favour Claude models.

### No judge

- **Pros:**
  - deterministic, offline and free;
  - every verdict comes from a rule you can read;
  - nothing leaves the machine.
- **Cons:** calls the rules do not recognize are allowed.
- **Setup:** none. This is the default.

### Claude Haiku 5.5 through Anthropic's endpoint

```yaml
judge:
  enabled: true
  base_url: https://api.anthropic.com/v1
  model: claude-haiku-5-5
  api_key_env: ANTHROPIC_API_KEY
```

- **Pros:**
  - near the top on accuracy;
  - about 2.5 s at p95, low cost;
  - writes a one-sentence reason the agent and you can read.
- **Cons:**
  - Anthropic describes this endpoint as "not considered a long-term or production-ready solution for most use cases";
  - it needs a workspace-scoped key, because applygate does not send the `anthropic-workspace-id` header;
  - calls go to Anthropic;
  - `reasoning_effort` is accepted and ignored.

### Claude through the `claude` CLI

```yaml
judge:
  enabled: true
  backend: command
  command: ["sh", "/path/to/examples/judge/claude-cli.sh"]
  timeout: 20s
```

- **Pros:**
  - no API key, because it uses the `claude` CLI's own login;
  - the most accurate Claude path measured on the fourth set;
  - writes a reason.
- **Cons:**
  - each call starts the CLI, so a judged call takes 3 to 4 s;
  - it needs `claude` and `jq` on PATH;
  - it uses your Claude plan;
  - it was not scored on the fifth set.

### Gemini 3.8 Flash

```yaml
judge:
  enabled: true
  base_url: https://generativelanguage.googleapis.com/v1beta/openai
  model: gemini-3.8-flash
  api_key_env: GEMINI_API_KEY
  timeout: 20s
```

- **Pros:**
  - the most accurate judge on both the fourth and fifth sets;
  - writes a reason;
  - very consistent between runs.
- **Cons:**
  - the slowest: about 5 s at the median and 9 to 10 s at p95;
  - some calls take longer than 10 s, and a timed-out call is left to the rules, so it needs `timeout: 20s`;
  - cost per call not measured;
  - calls go to Google.

### Jev (decision model)

```yaml
judge:
  enabled: true
  backend: command
  command: ["sh", "/path/to/examples/judge/jev.sh"]   # key in TYPESAFE_API_KEY
```

- **Pros:**
  - the fastest and cheapest, at under 0.7 s at p95;
  - a probability for each verdict.
- **Cons:**
  - slightly less accurate than Haiku;
  - no written reason (the reason lists the probabilities);
  - needs `curl` and `jq`;
  - calls go to TypeSafe AI.

### OpenAI's Decisions API (`gpt-6-luna`)

```yaml
judge:
  enabled: true
  backend: command
  command: ["sh", "/path/to/examples/judge/openai-decisions.sh"]   # key in OPENAI_API_KEY
```

- **Pros:**
  - fast, at under 0.7 s at p95;
  - no verdict changed across repeated runs;
  - a probability for each verdict.
- **Cons:**
  - the fewest catches of the measured judges, missing most credential reads;
  - it refuses some calls, which leaves the rule decision;
  - no written reason;
  - calls go to OpenAI;
  - the account needs API credits, and an empty account fails every call with HTTP 429.

### A local model, or another provider

```yaml
judge:
  enabled: true
  base_url: http://localhost:11434/v1   # for example Ollama; or any provider's OpenAI-compatible URL
  model: <model id>
  # api_key_env: PROVIDER_API_KEY       # when the endpoint needs a key
```

- **Pros:** with a local server, nothing leaves the machine and nothing is billed.
- **Cons:** accuracy, false escalations and latency are unknown until measured. The experiment's runner (`go run ./experiments/model-judge/eval -backend openai -base-url … -models …`) scores any endpoint on the held-out sets.

### How the endpoint is used

- **Request:** the answer is asked for as a JSON schema (`response_format` with `strict: true`). An endpoint that ignores that still works when the model replies with the JSON object.
- **Key:** read from the variable `api_key_env` names. With none set, no key is sent, which suits a local server. The key never goes in the config file.
- **`reasoning_effort`:** sent only when you set it.
- **Testing:**
  - Anthropic's and Gemini's endpoints were called live;
  - Jev and the Decisions API were called live through their scripts;
  - for other providers the settings follow each provider's published API shape, and only the request format is tested, against a local test server.
- **An unfinished choice:** `enabled: true` without `base_url` and `model` (or a `command`) means the judge is not asked. The rules decide as they do without it, the decision log says why, and `applygate doctor` warns.

### A program instead of an endpoint

The command backend runs any program you name. That is how the `claude` CLI, the decision models, another gateway or your own logic plug in.
- **Input:** one request as JSON on stdin, `{"system", "prompt", "schema", "call"}`.
- **Output:** `{"verdict": "allow"|"ask"|"block", "reason": "..."}` on stdout.
- **Anything else** counts as an error. A non-zero exit or running past the timeout leaves the rule decision. Output without a verdict is asked about outside a disposable environment. When the output holds several JSON objects, the last one with a `verdict` is the answer.

The scripts in [`examples/judge`](../examples/judge) take `APPLYGATE_JUDGE_MODEL` to choose another model.

### All settings

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turn the judge on (user config); a repository config may only set `false`. |
| `backend` | `openai` | `openai` (the OpenAI chat completions format, any provider) or `command`. |
| `base_url` | none; required for `openai` | The endpoint. |
| `model` | none; required for `openai` | The model id. |
| `api_key_env` | none (no key sent) | Environment variable holding the key. |
| `reasoning_effort` | not sent | Passed through as `reasoning_effort`. |
| `command` | none; required for `command` | Program and arguments. |
| `timeout` | `10s` | Per call. The hook's whole run, the rules, the judge, approvals, the log and telemetry included, has 29 seconds, one under the Claude Code plugin's 30-second hook timeout. The judge gets what is left of that, less 3 seconds for its process to exit and for the log; telemetry gets what is left after the verdict, or nothing. |
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
- **The cache:** asks and blocks are cached for 24 hours in `judge-cache.json` next to the log, which is a guard path, so a repeated call does not pay the model again. An allow is never cached, so a pre-filled cache cannot let a call skip the judge, and an entry dated in the future is ignored. Entries are keyed on the endpoint and model, or the whole command line of a command backend. `applygate check` keeps its own cache, `judge-cache-check.json`.
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
| Claude Haiku 5.5, Anthropic's endpoint | 70 | 4 | 2.5 s | $0.00022 |
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
- **Through Anthropic's endpoint:** it caught 62 to 63 on the fourth set over three runs, missing three calls the CLI asked about; why the paths differ is not established. `reasoning_effort` is accepted and changes nothing measurable.
- **On real agent traffic** from a week of Terraform work, the judge escalated none of 162 calls; 11% of the shell calls reached it.

**Live in headless Claude Code 2.1.314 on macOS,** with both Anthropic's endpoint ([review/judge-live, 2026-11-02](../review/judge-live/2026-11-02-default-endpoint.md)) and the command backend ([2026-11-01](../review/judge-live/2026-11-01-claude-code.md)):
- `pulumi destroy` on a protected stack was blocked;
- `pulumi preview` was judged and allowed;
- printing a Vault password was asked about, and did not run;
- `ls` was not sent to the judge (command-backend run).

With Anthropic's endpoint the hook took 1.2 to 3.0 s per judged call, against 3.3 to 3.9 s with the command backend, which has to start the `claude` CLI. Gemini, Jev and `gpt-6-luna` were run through `applygate check`, not inside an agent.

**Not measured:**
- **Any provider or model other than those above.** Accuracy, false escalations and latency are unknown until measured. The experiment's runner (`experiments/model-judge/eval -backend openai -base-url … -api-key-env …`, or `-backend command`) scores any OpenAI-compatible endpoint or adapter on the same held-out sets.
- **Anthropic's endpoint's long-term support.** Anthropic describes it as "not considered a long-term or production-ready solution for most use cases".
- **Agents other than Claude Code, and an interactive session.** Codex, an interactive session's ask prompt, and `applygate approve` for a judge's block are covered by tests only.

## Limits

- **A model can be wrong.** It missed up to three calls of each held-out set, mostly writes whose effect depends on context it cannot see, and it can be fooled in ways the sets did not try. The rules stay the guarantee; the judge is extra coverage.
- **Some calls skip the judge.** The filter keeps local work away from the model: reads inside the working tree, builds, tests, local git. So a destructive call that looks like local work is not judged, for example `git log -p` printing a key from history.
  - **Not local:**
    - a program started through its own options (`git -c`, `git config` that sets a value, `tar --to-command`, `sort --compress-program`, `rg --pre`, `go test -exec`, `go build -toolexec`, `go env -w`);
    - `mvn`, `gradle`, `dotnet` and `npm init`;
    - a forced `git push`, also in clustered flags (`-uf`);
    - a file the shell writes outside `/tmp` (a redirect, `tee`, `sed -i`), because the next step may run it;
    - a path outside the session's working directory once `cd` is followed;
    - reads of Terraform state, `.tfvars`, `.vault-token`, `.my.cnf`, `.s3cfg`, `.boto` and CLI credential directories.

    These go to the judge.
  - **The cost:** on the agent trial's 162 calls, 111 go to the judge, against 102 before.
- **Latency.** A judged call waits for the model. With Claude Haiku 5.5 that was 1.5 to 1.8 s at the median and 2.6 to 3.6 s at p95 in the measurements; with Gemini 3.8 Flash it was 5.1 s and 9.4 s; with Jev, 0.46 s and 0.56 s; with `gpt-6-luna`, 0.40 s and 0.74 s. A cached answer costs nothing.
- **A timeout means no judgement.** A call that runs past `timeout` is left to the rules, which allow it. Set the timeout above your endpoint's slowest answers. The judge never runs past 26 seconds after the hook started, whatever `timeout` says (the budget above).
- **Your data goes to the endpoint you configure.** Use a local server or a provider whose data terms you accept. Turn it off per repository with `judge: {enabled: false}`.
- **Workspace keys.** Anthropic's compatible endpoint needs an `anthropic-workspace-id` header for keys not scoped to a workspace, which applygate does not send. Use a workspace-scoped key.
