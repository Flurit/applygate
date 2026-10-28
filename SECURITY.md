# Security policy

seatbelt is a safety tool, so a flaw in it can let a destructive action through. Please report vulnerabilities privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability** (or go to <https://github.com/Flurit/seatbelt/security/advisories/new>). The report is visible only to the maintainers.

Please do **not** open a public issue, pull request or discussion for a suspected vulnerability.

Include what you can:

- the seatbelt version (`seatbelt version`) and the agent and version (Claude Code, Codex, …);
- the tool call or command, the working directory layout and the relevant `.seatbelt.yaml`;
- the verdict you got and the one you expected;
- for plan-gate issues, the `terraform show -json` output with secrets and account IDs removed.

Never send real credentials, state files or unredacted plans.

## What counts

In scope:

- **Bypasses:** a command, tool call or saved plan that should be asked about or blocked under the documented policy ([docs/policy.md](docs/policy.md)), but is allowed. Examples: shell constructs the analyzer resolves wrongly instead of refusing, or plan changes the gate misses.
- **Fail-open:** an input that makes seatbelt crash, hang or exit in a way the agent treats as "proceed" when the configuration says it should fail closed.
- **Self-protection:** an agent tool call that changes hook settings, seatbelt's config or its decision log without being blocked.
- **Log leaks:** secrets written to the decision log unredacted.
- **Release integrity:** problems with release signing, provenance or `install.sh` verification.

Out of scope: anything [docs/limits.md](docs/limits.md) and [docs/threat-model.md](docs/threat-model.md) already list as not defended (for example MCP tool calls, code in other languages that mentions no infrastructure tool, or an agent with another path to cloud credentials). Reports that show one of these limits is worse than documented are welcome.

## What to expect

- Acknowledgement within 3 working days.
- An initial assessment within 10 working days.
- A coordinated fix and a GitHub security advisory. Fixes ship in a new release; tags of published releases are never moved.
- Credit in the advisory if you want it.

seatbelt is pre-1.0. Only the latest release receives security fixes.

## Verifying releases

Every release publishes `checksums.txt`, signed keylessly with cosign (`checksums.txt.sigstore.json`), plus a GitHub build-provenance attestation for each archive. See [Verify a download](README.md#verify-a-download).
