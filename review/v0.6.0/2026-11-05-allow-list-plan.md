# Allow-list rewrite: staged plan

Follows [the reassessment](2026-11-05-reassessment.md), recommendation 3. The aim is that in a protected tier a program is plain only in a form that is listed, so an option or spelling nobody thought of is an ask, not an allow. The cost target: no verdict change on the 162-call agent trial; about 13% more asks on benign controls is accepted.

## Mechanism

`internal/shell/allow.go` holds one matcher (`prog`) and the tables. An entry lists options by exact name (no GNU abbreviation), says which take a value, how many operands, and rules over the options seen. A word that starts with a dash is an option wherever it stands (GNU permutes, BSD does not); an unresolved word that may be an option is not plain, except for programs whose real option set cannot write or run anything (`loose`). `inert` is the audited list of programs that keep "any arguments"; a test fails when a nil shape is not on it.

## Conformance

`allow_conformance_test.go` runs every listed option with the real program of the machine (CI runs Linux and macOS) in a scratch directory beside a bystander directory and a canary program on `PATH`. An entry fails when the run changes anything outside the scratch directory, creates a file its operands do not name, or starts the canary. A second test shows the check fails for `sort -o`.

## Stages

1. **Writers and the programs with output options that had no shape** (this change): `rm mkdir touch chmod ln cp mv tee sort uniq tree diff xxd base64 gzip gunzip unzip date hostname file gofmt tfsec gsutil find`; the rest of the old nil list is audited in `inert`.
2. **Programs with a deny list**: `curl wget zip yq rg sed tar printf` and the cloud and container CLIs' option tables (`aws`, `gh`, `docker`, `kubectl`, `helm`, `trivy`, `kustomize`), by listing what is understood. The conformance test gains per-entry sample invocations for programs that need an operand shape (archives, requests).
3. **Grammars**: redirect targets, builtins and `cd`, assignments and wrappers, as positive grammars for protected tiers (literal single target, one-operand `cd`, closed charset), replacing the per-shell handling that rounds 10 and 11 extended.
4. **Verbs**: `git` and cloud CLI subcommands by list, and the Terraform option table (the ten criticals no shell allow-list reaches are Terraform and provider-scan semantics: init and provider execution, `tfquery`, `-backend-config`, module scans, `graph -type=plan`, a config over 1 MiB, an unresolved `-chdir`; they need rules of their own).
5. **Remove the writer tables** (`writeTargets`, `outputOpts`) once the allow-list carries the write kinds, and run the effects oracle (recommendation 5) in CI.

Each stage: unit tests, conformance, the attack pack, selftest, the trial replay in prod, staging and dev, and a limits entry that states the new asks.
