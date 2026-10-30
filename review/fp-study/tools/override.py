#!/usr/bin/env python3
"""Write the study's Terraform override files into a root module.

    override.py ROOT TAG

Every `provider "aws"` block in ROOT (the default one and each alias) gets an
override that pins LocalStack's dummy credentials and a `default_tags` block
whose `fp_study` tag is TAG; flipping TAG between plans is the study's
routine tag change. Endpoints come from AWS_ENDPOINT_URL (compose.yaml). A root
with no aws provider block of its own gets a plain provider file instead,
since an override needs a base block. A root that declares a backend or a
Terraform Cloud block gets a local backend.

Reads .tf files only; runs nothing.
"""
import os
import re
import sys

PROVIDER = re.compile(r'^\s*provider\s+"aws"\s*\{', re.M)
ALIAS = re.compile(r'^\s*alias\s*=\s*"([^"]+)"', re.M)
REMOTE = re.compile(r'^\s*(backend\s+"[^"]+"|cloud)\s*\{', re.M)

OURS = ("fpstudy_override.tf", "fpstudy_provider.tf")


def block(text, start):
    """Return the body of the block whose opening brace is at text[start-1]."""
    depth, i = 1, start
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start:i - 1]


def provider_body(tag, alias=None):
    lines = ['provider "aws" {']
    if alias:
        lines.append(f'  alias                       = "{alias}"')
    lines += [
        '  access_key                  = "test"',
        '  secret_key                  = "test"',
        "  skip_credentials_validation = true",
        "  skip_metadata_api_check     = true",
        "  s3_use_path_style           = true",
        "  default_tags {",
        f'    tags = {{ fp_study = "{tag}" }}',
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def main():
    root, tag = sys.argv[1], sys.argv[2]
    aliases, remote = [], False
    for name in sorted(os.listdir(root)):
        if not name.endswith(".tf") or name in OURS or name.endswith("_override.tf") or name == "override.tf":
            continue
        text = open(os.path.join(root, name), encoding="utf-8", errors="replace").read()
        for m in PROVIDER.finditer(text):
            a = ALIAS.search(block(text, m.end()))
            aliases.append(a.group(1) if a else None)
        remote = remote or bool(REMOTE.search(text))
    for f in OURS:
        p = os.path.join(root, f)
        if os.path.exists(p):
            os.remove(p)
    header = "# Written by review/fp-study/tools/override.py; not part of the repository.\n"
    over = []
    if remote:
        over.append('terraform {\n  backend "local" {}\n}\n')
    if aliases:
        seen = []
        for a in aliases:
            if a not in seen:
                seen.append(a)
                over.append(provider_body(tag, a))
    else:
        with open(os.path.join(root, OURS[1]), "w") as fh:
            fh.write(header + provider_body(tag))
    if over:
        with open(os.path.join(root, OURS[0]), "w") as fh:
            fh.write(header + "\n".join(over))
    print(f"providers: {['default' if a is None else a for a in aliases] or ['(none; plain provider file)']}; remote backend overridden: {remote}")


if __name__ == "__main__":
    main()
