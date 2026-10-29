# Changelog

## Unreleased

- `applygate apply <planfile>`: the human door. Judges a saved plan exactly as the hooks judge `terraform apply <planfile>` (tier, preflight, plan gate), logs the decision with agent `human`, refuses a block, asks for the environment name to be typed back on an ask, and only then runs `terraform` or `tofu` (`--engine`). Outside a terminal an ask is refused unless `--yes`, which never applies in a protected tier.

## v0.2.0 (2026-10-29)

- Renamed the project from seatbelt to applygate. Binary `applygate`, config `.applygate.yaml`, hook commands `applygate hook claude|codex`, user config `~/.config/applygate/config.yaml`, decision log `~/.local/state/applygate/decisions.jsonl`, installer variables `APPLYGATE_*`, Go module `github.com/Flurit/applygate`.
- Compatibility for one release: `.seatbelt.yaml` is read with a deprecation note; the old user config and log paths are used when the new ones do not exist; hook entries that call `seatbelt` are recognised, and a `seatbelt` shim binary in the release archive forwards to `applygate`; `SEATBELT_*` installer variables are honoured with a warning; the legacy file names stay guard-protected.
- Carried from main since v0.1.4: host capability matrix (`applygate hosts`, `docs/hosts.md`), fail-closed tier resolution when a host does not report the command directory, bounded planfile search, user-scope hook installs.

## v0.1.4 and earlier

Released as seatbelt; see the GitHub releases and `docs/project/ACCEPTANCE.md`.
