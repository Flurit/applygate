# Strict shapes: measurement (workstream 9)

Decision D-3 of the [fix plan](2026-11-02-fix-plan.md) asked for a strict mode to be measured before deciding whether to ship it. The candidate rule:

> In a protected tier, allow only commands whose words all resolved and whose structure is a plain list or pipeline (`&&`, `||`, `|`, `;`) of known programs. Ask about everything else.

The measurement is `go run ./experiments/strict-shapes -bin bin/applygate`, run on 2026-11-03 against milestone 2 (`fix/m2-analyzer`). The tool never runs the commands.

## What was measured

- **"Known programs":** a list of about 120 programs in the tool, covering shell builtins, text and file tools, git, build tools and the infrastructure CLIs. Interpreters and shells are not on it, because their code is opaque.
- **Not plain:**
  - the command does not parse;
  - it uses any other construct: `for`, `if`, functions, subshells, `$(…)`, `${x:-…}`, declarations, `$'…'` or background;
  - the analyzer reports a problem;
  - a word is unresolved;
  - a top-level program is not on the list.
- **New ask:** a benign command that is not plain and that applygate allows today in the fixture repository's protected directory (`harness/pack/fixtures/repo/envs/prod`, strict mode, no judge). The mode would add exactly these asks.
- **Benign traffic:**
  - **the agent-driven trial:** 162 real Claude Code and Codex shell calls on five public Terraform repositories;
  - **the OSS corpus:** the 1,158 lines the hand review labelled `allow`, recorded at commit `149ab67`. These are lines from documentation, workflows and scripts, so many are tool output in code blocks (`kubectl get` tables, `tree` output) rather than commands. That inflates this set's count.
  - **the benign calls of both packs.**
- **Attacks:** the dangerous calls of the scenario pack and of the review's attack pack. A not-plain attack is one the mode would ask about even if the analyzer missed it.

## Results

Variant A, where every word must resolve:

| Set | Commands | Not plain | New asks in a protected tier |
|---|---|---|---|
| Agent trial (benign) | 162 | 51 | **48 (30%)** |
| OSS corpus (benign) | 1,158 | 785 | 714 |
| Scenario pack (benign) | 48 | 10 | 8 |
| Attack pack (benign) | 17 | 1 | 1 |
| Scenario pack (dangerous) | 95 | 22 | n/a |
| Attack pack (dangerous) | 135 | **56 (41%)** | n/a |

Variant B, where only the program names must resolve (`-args=false`):

| Set | Commands | Not plain | New asks in a protected tier |
|---|---|---|---|
| Agent trial (benign) | 162 | 29 | **26 (16%)** |
| OSS corpus (benign) | 1,158 | 762 | 692 |
| Scenario pack (benign) | 48 | 10 | 8 |
| Attack pack (benign) | 17 | 1 | 1 |
| Scenario pack (dangerous) | 95 | 21 | n/a |
| Attack pack (dangerous) | 135 | **56 (41%)** | n/a |

Why the 48 real agent calls in variant A are not plain:

| Reason | Calls |
|---|---|
| An unresolved word, mostly an unquoted glob (`cat *.tf`, `grep --include=*.tf`) | 23 |
| `python3 -c` or `python3 - <<EOF` edits | 11 |
| A `for` loop | 5 |
| `export PATH=…` | 4 |
| `${VAR:-unset}` | 2 |
| `awk`, `strings` | 2 |
| A subshell | 1 |

## Reading

- **The cost is high on real traffic:** one call in three (variant A) or one in six (variant B) that an agent made in the trial would become an ask in a protected tier. The calls are reading files, globbing `*.tf`, editing with Python and looping over directories. These are the calls an agent makes most while working on Terraform.
- **The benefit is backup only:** fewer than half of the known attacks (56 of 135) have a shape the mode would catch. The other 79 are plain commands, such as `TERRAFORM destroy`, `gcloud storage rm …` and `kubectl --cluster prod delete …`. The analyzer has to classify those correctly whatever the mode. After milestone 2, it catches all 135.
- **Requiring every argument to resolve buys nothing:** it adds 22 asks on real calls and catches no extra attacks.

## Recommendation

Don't make strict shapes the default. Whether to ship it as an opt-in setting is a product decision with these numbers:

- **(a) Don't ship it in v0.6.0 (recommended).** Exact-or-unresolved analysis (workstream 8) already closes every C finding, and the red-team round will show whether new bypasses are shape-based. Revisit then.
- **(b) Ship variant B as an opt-in user setting, `strict_shapes: true`, for teams that accept the asks.** This means about a day of work for the setting, its documentation and tests, plus the ask message.

The tool and these numbers stay in `experiments/strict-shapes` either way.
