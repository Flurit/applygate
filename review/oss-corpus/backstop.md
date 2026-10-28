# Unknown-wrapper backstop: effect on the open-source corpus

Date: 2026-10-28. Change: the generic backstop for unrecognized wrappers, named handling for `direnv`, `mise`/`rtx`, `asdf`, `devbox`, `nix`/`nix-shell`, and the `wrappers:` config option (see `docs/policy.md`).

## Result

Re-running the corpus (`review/oss-corpus/run.sh`, the same pinned commits and trial configs) changed **no verdict** among the 1,334 commands, either with the trial configs or with no config. The new rule caused **no text-mention false positives** on this corpus. False positives stay at 6 of 1,259 runnable commands (0.48%).

The committed `results/*-after.jsonl` files still match a fresh run and were not changed.

## How much the corpus exercised the rule

Little. 230 corpus commands contain `terraform`, `tofu` or `terragrunt`. The backstop and the named runners fired on **none** of them (checked by scanning every action's `via` chain for `(unrecognized wrapper)` and the runner names):

- The only commands where an engine word is a standalone argument of another program are 8 `gds aws <role> -- terraform …` lines in govuk-infrastructure. `gds aws` is a named credential wrapper (since v0.1.2), so they never reach the backstop.
- Every other mention is inside a quoted string (`git commit -m "…terraform…"`, `echo "…"`), an argument of a text program (`grep`, `echo`, `cat`), part of a longer word (`terraform/`, `terraform-docs`, `hashicorp/terraform`), or the program itself.

So this re-run shows the rule does not misfire on real documentation and CI text, but it does not show the rule catching real wrappers; the corpus has no unrecognized wrappers. The scenario pack covers that (D58–D64).

## Controls in the scenario pack

Allowed in a protected directory (B35–B42): `git commit -m "docs: never run terraform destroy"`, `grep -rn "terraform destroy" docs/`, `echo terraform destroy`, `man terraform`, `my-linter --check terraform/`, `company-run prod-admin aws s3 ls` (configured wrapper, read-only), `brew install terraform tflint`, `asdf install terraform 1.9.0`.

Not allowed in a protected directory (D58–D64): `madeup-tool run -- terraform destroy -auto-approve`, `foo exec prod terraform apply -auto-approve`, `direnv exec . terraform destroy`, `mise exec -- tofu destroy`, `devbox run -- terraform destroy`, `nix-shell --run 'terraform destroy'`, and `company-run prod-admin aws s3 rb … --force` from a QA directory (configured wrapper; the profile makes it protected).

## Known gaps

- A wrapper that takes the whole command as **one quoted argument** without a shell-string flag (`foo run "terraform destroy"`) is not unwrapped: the request was not to look inside quoted strings, because that is where text mentions live. Flags that take a command line (`--run`, `--command`, `-c`, `--cmd`, `--exec`, `-x`, `--shell-command`) are the exception, when their value starts with an engine.
- The backstop only triggers on `terraform`, `tofu` and `terragrunt`. A wrapper around `aws s3 rb` or `kubectl delete` needs a named wrapper or a `wrappers:` entry in the config.
