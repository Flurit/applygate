# v0.6.0 round-7 fix plan

Round 7 ([report](2026-11-04-red-team-round-7.md)) found 21 critical issues on main at 8f013e4.

**The user's decision on 2026-11-04: options 1 and 3 together.**
- Fix the criticals by turning the four structural causes into rules rather than lists.
- Bring the OS-level backstop forward, so that a call that gets past the hook cannot reach production.

The promise is not narrowed.

## Milestones

### R7-1: the four rules, and the criticals they do not cover

| Rule or area | Findings | Fix |
|---|---|---|
| **Unknown, not absent** | 7C10, 7C11, 7C17 | An unresolved value in a tier signal makes the target protected. This covers a workspace, profile, kube context, project or subscription, a backend config, `-state`, `-backup`, a planfile, `TF_CLI_ARGS*`, `KUBECONFIG`, `CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR` and a credential runner's profile. Variables that `read`, `mapfile`, `readarray`, `getopts` and `printf -v` assign go through the same check as `NAME=`. Relative config paths are joined with the command's directory. |
| **Written earlier means not plain** | 7C12, 7H17, 7H18 | A step that can write a directory's configuration, `.terraform`, lock file, state or planfile makes a later terraform call in that directory not plain. The writers are git's tree-rewriting subcommands, `init -from-module`, `cp`, extraction and the shell writers. That later call is then judged as unknown for its tier signals. Stream paths are cleaned and resolved. `plan -state=X -out=p` gives `p` X's tier. |
| **Ask the program, do not imitate it** | 7C1, 7C2, 7C4, 7C5, 7C13, 7H5 | The git directory is found by the hook's hardened git (`rev-parse`) on the physical path, and must agree with applygate's own walk. `--bare`, `--git-dir` and `--work-tree` are not plain. A remote is accepted only when it is a network URL with a known scheme, an scp-like address, or a configured remote; `archive --remote` is a network command. Terraform configuration is read with the HCL and JSON parsers, `.tofu` included. Any subcommand outside a short read-only list (`fmt`, `version`, `output`, `state list`, `workspace list/show`, `providers`, `graph -type=plan` and the like) counts as starting providers. A provider or backend block with `exec`, `credential_process`, `shared_config_files`, `shared_credentials_files`, `config_path` or `profile` runs programs, unless the file it names is checked. Every aws provider counts as a tier signal, whatever its local name and in whatever module. |
| **Managed judge and host** | 7C19, 7C20 | Under a managed install the judge runs with a root-owned `HOME` and working directory, no `APPLYGATE_JUDGE_*`, no proxy variables and `PYTHONNOUSERSITE=1`, and its settings come from the system config. The openai backend uses no proxy. `doctor --managed` and the install refuse, or warn on, a user-writable host CLI, and the known host binary locations are guard paths. |
| **Shapes and shell** | 7C3, 7C6, 7C7, 7C8, 7C9, 7C14, 7C15, 7C16, 7C21 | `gh` asks in a repository the git check would ask in, and `gh repo clone … --` asks. zsh's `chdir`, `nocorrect`, `-`, `builtin` and `TRAP*` functions are handled. The `sed` shape reads `--` and the valued options. `helm` and `trivy --kubeconfig` ask. The go env file is a guard path, and `go list -export`/`-compiled` ask. Terragrunt units go through `terragruntSignals`. Container `-e` becomes the action's environment; in-container paths are mapped back through `-v`, and `--env-file` makes the environment unknown. `{}` inside a `find -exec` argument is an unresolved placeholder. `cd`, `pushd`, `popd` and `exec` in persistent-shell input are tampering. |
| **Guard** | 7C18 | A guard path is compared as written as well as resolved, so a symlink on `PATH` is guarded where it sits. Under a managed install, the hook's own git must be root-owned. |

### R7-2: OS-level credential backstop

Design first, then build; the design needs the user's choices. The goal is that the agent's processes cannot use production credentials without a person, whatever the hook decides. The candidates:
- a broker that holds the protected profiles' credentials outside the agent user's reach and hands them out only on a person's approval;
- moving the protected profiles to roles that the agent's credentials cannot assume;
- a sandbox (macOS `sandbox-exec` profiles, Linux user namespaces) around the agent.

### R7-3: the highs and mediums

The remaining 22 highs, and the mediums open since round 6.

### Round 8

Briefed on R7-1 and R7-2. Its `env.sh` also sets `TF_CLI_CONFIG_FILE`, `TF_PLUGIN_CACHE_DIR` and `GH_CONFIG_DIR` inside the reviewer's directory, and the briefs forbid running shipped judge scripts and networked CLIs without a local endpoint.
