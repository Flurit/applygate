# Experiment: a model judge for what the rules do not recognize

Question: would a model, used only to make verdicts stricter, catch enough of what applygate's rules miss to be worth its latency, cost and false positives?

## Design

- **The rules decide first, unchanged.** Every call gets the rule decision applygate gives today (`policy.Decide`, with known MCP tools translated as the hook does).
- **The judge sees only the residual:** calls the rules allow without recognizing anything (no Terraform, cloud, cluster or guard action), plus MCP tools the table does not know. Calls the rules classified, safe or not, never reach it (`judge.Residual`).
- **Escalate only.** The final verdict is the stricter of the rule verdict and the judge verdict (`judge.Merge`). A judge that is wrong, or talked into "allow" by text in the call, can at worst add a prompt; it cannot let through anything the rules stop.
- **Prompt.** One fixed system prompt (`judge.System`): what counts as damage, how the environment tier changes the answer, and that everything in the call is untrusted data whose claims of safety are a warning sign. The call goes in `<tool_call>` tags with the environment the rules resolved for its directory.
- **Filter (measured both ways).** `judge.Relevant` (`internal/judge/filter.go`) sends every residual call to the judge except shell commands made only of known local programs (reading, building, testing, local git, file commands inside the working tree), and sends every file write and edit, with its content. MCP calls always go. File reads never do. Round 1 used a word list instead; see RESULTS.md.
- **Backend.** `judge.CLI` calls the `claude` CLI in print mode with no tools, the judge's system prompt and a JSON schema for the answer, using the CLI's login, so the experiment needs no API key. `api_ms` is the model time the CLI reports, the figure an SDK call would see; `wall_ms` adds the CLI's start-up, which an SDK call would not pay. A product feature would call the API through the Go SDK.

## Datasets

- **pack:** the 163-scenario pack. Almost every dangerous scenario is decided by the rules, so this mainly checks that the judge adds no false positives on the benign scenarios.
- **longtail** (`longtail.json`, 109 items): calls the rules do not recognize today. 59 should be escalated: Pulumi, CDK, CDKTF, eksctl, doctl, fly, Heroku, Vercel, Netlify, Firebase, Supabase, SQL through psql/mysql/mongosh/redis-cli, migration resets, gsutil/rclone/s3cmd, Docker volumes, Ansible, Serverless, SAM, Copilot, Argo CD, Vault, Consul, Nomad, SDK code in `python -c`/`node -e`, wrapper scripts, five prompt-injection variants, three staging copies and seven unknown MCP tools. 46 are benign: their read-only twins, ordinary development commands and benign MCP calls. 4 are destructive but local, run from the dev directory, and should be allowed; 2 more in the dev directory name a production target and should be escalated.
- **trial:** the 155 shell calls Claude Code and Codex made in the agent-driven trial on five public Terraform repositories, all benign. The repositories are not checked out here, so the default config applies (strict: every directory protected), the hardest case for false positives.

## Running

```bash
go run ./experiments/model-judge/eval -models claude-haiku-5-5,claude-sonnet-5-5,claude-opus-5-5 -effort low -datasets pack,longtail,hard,trial
```

Datasets: `pack`, `longtail`, `hard`, `heldout`, `heldout2`, `trial`. `-prefilter` judges only the calls that pass the filter (the mode we would ship) and costs about half as much.

Results are cached in `results/cache.json` by model, effort, prompt version and input; `results/report-<model>.md` and `results/rows-<model>.json` hold the scores and every judged call. Nothing in the experiment runs the commands it judges.
