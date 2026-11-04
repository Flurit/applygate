# v0.6.0 round-7 fix plan

Round 7 ([report](2026-11-04-red-team-round-7.md)) found 21 critical issues on main at 8f013e4.

**The user's decision on 2026-11-04: options 1 and 3 together.**
- Fix the criticals by turning the four structural causes into rules rather than lists.
- Bring the OS-level backstop forward, so that a call that gets past the hook cannot reach production.

The promise is not narrowed.

## Milestones

### R7-1: the four rules, and the criticals they do not cover

**Built** on branch fix/round-7, with reproductions in `harness/pack_attack` (Y7*: 45 reproductions, 9 benign controls):
- `go test -race ./...` passes, including the attack pack (495 scenarios).
- Selftest: 163/163 exact. Replays: Claude 163/163, Codex 161/161. Decision latency p95 12.3 ms.
- Agent trial against main: in a protected directory 54 of 162 calls are asked about or blocked, against 51. The three new asks are two terraform calls after the same command wrote their configuration (one in a scratch directory) and `sed -i 's/…/' eks.tf` on macOS. Staging and dev: 13, against 12, the scratch-directory call. No new blocks.
- Two choices made while building, both recorded in docs/limits.md: input to a persistent shell is judged as protected rather than making every `cd` there tampering, and `sed -i` is read as this machine's sed reads it.

| Rule or area | Findings | Fix |
|---|---|---|
| **Unknown, not absent** | 7C10, 7C11, 7C17 | An unresolved value in a tier signal makes the target protected. This covers a workspace, profile, kube context, project or subscription, a backend config, `-state`, `-backup`, a planfile, `TF_CLI_ARGS*`, `KUBECONFIG`, `CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR` and a credential runner's profile. Variables that `read`, `mapfile`, `readarray`, `getopts` and `printf -v` assign go through the same check as `NAME=`. Relative config paths are joined with the command's directory. |
| **Written earlier means not plain** | 7C12, 7H17, 7H18 | A step that can write a directory's configuration, `.terraform`, lock file, state or planfile makes a later terraform call in that directory not plain. The writers are git's tree-rewriting subcommands, `init -from-module`, `cp`, extraction and the shell writers. That later call is then judged as unknown for its tier signals. Stream paths are cleaned and resolved. `plan -state=X -out=p` gives `p` X's tier. |
| **Ask the program, do not imitate it** | 7C1, 7C2, 7C4, 7C5, 7C13, 7H5 | The git directory is found by the hook's hardened git (`rev-parse`) on the physical path, and must agree with applygate's own walk. `--bare`, `--git-dir` and `--work-tree` are not plain. A remote is accepted only when it is a network URL with a known scheme, an scp-like address, or a configured remote; `archive --remote` is a network command. Terraform configuration is read with the HCL and JSON parsers, `.tofu` included. Any subcommand outside a short read-only list (`fmt`, `version`, `output`, `state list`, `workspace list/show`, `providers`, `graph -type=plan` and the like) counts as starting providers. A provider or backend block with `exec`, `credential_process`, `shared_config_files`, `shared_credentials_files`, `config_path` or `profile` runs programs, unless the file it names is checked. Every aws provider counts as a tier signal, whatever its local name and in whatever module. |
| **Managed judge and host** | 7C19, 7C20 | Under a managed install the judge runs with a root-owned `HOME` and working directory, no `APPLYGATE_JUDGE_*`, no proxy variables and `PYTHONNOUSERSITE=1`, and its settings come from the system config. The openai backend uses no proxy. `doctor` reports a user-writable `claude` or `codex`, the known install locations and names on `PATH` are guard paths, and installing or updating an agent CLI is tampering. |
| **Shapes and shell** | 7C3, 7C6, 7C7, 7C8, 7C9, 7C14, 7C15, 7C16, 7C21 | `gh` asks in a repository the git check would ask in, and `gh repo clone … --` asks. zsh's `chdir`, `nocorrect`, `-`, `builtin` and `TRAP*` functions are handled. The `sed` shape reads `--` and the valued options. `helm` and `trivy --kubeconfig` ask. The go env file is a guard path, and `go list -export`/`-compiled` ask. Terragrunt units go through `terragruntSignals`. Container `-e` becomes the action's environment; in-container paths are mapped back through `-v`, and `--env-file` makes the environment unknown. `{}` inside a `find -exec` argument is an unresolved placeholder. Input to a persistent shell is judged as protected, and a terraform call there that may start providers is not plain. |
| **Guard** | 7C18 | A guard path is compared as written as well as resolved, so a symlink on `PATH` is guarded where it sits. Under a managed install, the hook's own git must be root-owned. |

### R7-2: OS-level credential backstop

**Goal.** Once a call gets past the hook, it cannot reach production without a person. That has to hold whatever the hook decides: whatever the analyzer missed, and whatever the agent planted for a later call. Seven rounds show the hook's model of programs will keep missing routes. The backstop makes a miss cost a prompt for a person, not a production change.

**What it must withstand.** The agent's user runs the agent, so anything that user can read the agent can read: files in the home directory, the keychain items that user's processes can open without a prompt, and environment variables. So the production secret, or the power to mint one, must live where the agent's user cannot reach it. The person's approval must also come through a channel the agent cannot drive: not a terminal (the agent has one), and not a file.

**Options.**

| | A. Roles the agent cannot assume | B. Credential broker | C. Sandbox around the agent |
|---|---|---|---|
| **What it is** | Configuration and an audit, no new trusted code. The agent's profiles can only read production. Writes need a role whose trust policy requires MFA (`aws:MultiFactorAuthPresent`, a hardware key), assumed by a person. | A root-owned service (`applygate broker`, a launchd or systemd daemon as its own user) holds the protected profiles' source credentials. AWS profiles in `~/.aws/config` point `credential_process` at `applygate creds <profile>`, which asks the broker. Read-only role credentials are handed out at once; write-capable ones only after a person approves out of band. | The agent CLI is started inside an OS sandbox (macOS `sandbox-exec`, Linux bubblewrap or Landlock) that cannot read credential files or the keychain, and cannot reach cloud API endpoints except through the hook's own process. |
| **What applygate builds** | `applygate doctor --creds`: for each profile the agent's environment can use, asks STS who it is and simulates destructive actions in protected accounts (`iam simulate-principal-policy`); reports any profile that can write production. Docs with IAM examples for AWS, GCP and Azure. | The broker, the client, the approval channel, the install (managed only), credential caching and rotation. AWS first; kube, gcloud and az through their exec and credential plugins later. | A launcher (`applygate run claude`), profiles per OS, and a way to run approved production calls outside the sandbox. |
| **Approval channel** | The person's MFA device. | Touch ID or a macOS system dialog (LocalAuthentication, shown by a user agent the broker starts), or a push to the person's phone. On Linux, polkit with a password. The agent cannot press Touch ID; it can type a password into a terminal, so a password prompt there does not count. | Not needed for blocking; a person runs approved calls outside. |
| **Holds against an agent that sets out to get round it** | Yes, as far as the cloud's IAM holds. | Yes, if the broker's store is outside the user's reach (managed install) and the approval channel is physical. | Partly: sandbox profiles are deny-lists of paths and hosts, and the same enumeration problem returns (a new credential location, a new endpoint). `sandbox-exec` is deprecated on macOS. |
| **Cost to the user** | Setting up roles once; production applies go through a person's MFA. | Installing a daemon; a Touch ID press per production write session. | Every agent session runs in a sandbox; tools that need the network or other files break. |
| **Size** | Small: about a week, mostly docs and the audit. | Large: weeks; a new privileged service with its own threat model and review. | Medium, but fragile across OS versions. |

**Recommendation: A now, B next, not C.**
- **A** is the standard boundary and needs no new trusted code. It is the only option whose guarantee does not depend on applygate being right, and `doctor --creds` tells a user whether they have it.
- **B** is the product version of A for teams that want the agent to plan against production with read-only credentials and to apply with one approval. It needs a managed install and its own red-team round.
- **C** re-creates the enumeration problem at the OS layer.

**Decided on 2026-11-04: A.** Built on branch fix/round-7: `applygate doctor --creds` (AWS: identity, tier, and `iam simulate-principal-policy` over 16 destructive actions with MFA absent; Kubernetes: `kubectl auth can-i` over 4 destructive verbs per context), tested with stubbed CLIs, and `docs/credentials.md`. Not tested against a real AWS account or cluster. B stays the next step if the user wants the agent to apply with one approval.

**Choices that were put to the user:**
1. A, B or both, and in which order.
2. For B: the approval channel (Touch ID on macOS and polkit on Linux; or a phone push, which needs a service), and the clouds after AWS.
3. Whether a production write without the backstop in place should be refused by default under a managed install, or only reported by `doctor`.

### R7-3: the highs and mediums

**The 22 highs are built** on branch fix/round-7-highs, with reproductions in `harness/pack_attack` (Y7H*, 35 scenarios; 530 in all). Done: 7H1 to 7H4, 7H6 to 7H13, 7H16, 7H19 to 7H22 (7H5, 7H14, 7H15, 7H17 and 7H18 were fixed in R7-1). The agent trial's verdicts are unchanged in every tier. Four mediums came with them: `helm test`, the judge filter's `/usr/bin/env` and credential-file gaps, and the unsafe-Makefile rule.

Still open, as mediums and lows: the host-file and switch gaps (R2-10), self-approval through a TTY tool (R2-9), the redaction gaps (R5-3, R5-4), the lock-file check under a slow git (R5-5), the release cache and the Action's default version (R5-6, R5-7), `branch --unset-upstream` (R1-24), the read-only classes that have effects (R1-25), unseen writes (R1-26), repository configs claiming outside their tree and shadowing wrappers (R3-21, R3-22), and the lows.

### Round 8

Briefed on R7-1 and R7-2. Its `env.sh` also sets `TF_CLI_CONFIG_FILE`, `TF_PLUGIN_CACHE_DIR` and `GH_CONFIG_DIR` inside the reviewer's directory, and the briefs forbid running shipped judge scripts and networked CLIs without a local endpoint.
