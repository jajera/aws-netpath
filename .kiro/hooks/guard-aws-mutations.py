#!/usr/bin/env python3
"""Block mutating `aws` CLI calls from shell tools.

"Read-only by construction" is a documented guarantee of this project: nothing
here changes an AWS resource or host state, and enforcement is an explicit
allowlist of API actions rather than a convention (README, "Read-only by
construction"). A mutating `aws` CLI call issued from a shell tool sits outside
that allowlist and contradicts the guarantee, so it is refused here.

Read-only verbs pass: describe-*, list-*, get-*, search-*, `s3 ls`,
`sts get-caller-identity`.

The project's own binary is NOT this guard's business. `aws-netpath collect`,
`query`, `diagnose`, `test`, `firewall`, `compare`, `diff`, and `verify` are a
different executable from the `aws` CLI, and `verify` legitimately creates a
Reachability Analyzer analysis through the SDK — an intended, documented,
billable read of the network. Matching is therefore on the executable's basename
being exactly `aws`, never on a command merely containing the substring "aws".

Wired as a Kiro PreToolUse hook scoped to shell tools. Exit code 2 blocks the tool
call and returns stderr to the agent (https://kiro.dev/docs/hooks/).

To run a mutating call deliberately:

    export AWS_NETPATH_ALLOW_AWS_WRITE=1
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys

ALLOW_ENV = "AWS_NETPATH_ALLOW_AWS_WRITE"

# Strings longer than this are treated as file content, not a command line. A
# README or spec document quoting `aws ec2 create-vpc` is documentation, not an
# invocation.
MAX_COMMAND_CHARS = 2000

# Read-only AWS CLI verbs. Anything else on an `aws` invocation is treated as
# mutating: refusal is the default, which is the same stance internal/guardrail
# takes towards its action allowlist.
READ_ONLY_VERBS = frozenset(
    {
        "describe",
        "list",
        "get",
        "head",
        "search",
        "lookup",
        "select",
        "query",
        "check",
        "estimate",
        "simulate",
        "validate",
        "test",
        "wait",
        "help",
    }
)

READ_ONLY_S3_SUBCOMMANDS = frozenset({"ls", "presign"})

# Command wrappers that delegate to the real executable, so `sudo aws ec2
# create-vpc` is still an `aws` invocation.
WRAPPERS = frozenset({"sudo", "env", "time", "nice", "nohup", "command", "xargs", "stdbuf"})

# Statement separators, so `cd /tmp && aws ec2 create-vpc ...` is seen.
STATEMENT_SPLIT = re.compile(r"\|\||&&|[;&|\n]|\$\(|`")

# Shell keywords that can precede a command inside a compound statement.
LEADING_KEYWORDS = frozenset({"then", "do", "else", "elif", "if", "while", "until", "!"})


def iter_strings(node: object):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from iter_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from iter_strings(value)


def candidate_commands(raw: str) -> list[str]:
    """Every plausible command string in the payload.

    The payload schema is not depended upon: any string field is inspected, with
    the raw text as a fallback when the payload is not JSON.
    """
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        payload = None

    candidates = [raw] if payload is None else list(iter_strings(payload))

    return [
        text
        for text in candidates
        if 0 < len(text) <= MAX_COMMAND_CHARS and "aws" in text
    ]


def statements(command: str) -> list[str]:
    return [part.strip() for part in STATEMENT_SPLIT.split(command) if part.strip()]


def tokenise(statement: str) -> list[str]:
    try:
        return shlex.split(statement)
    except ValueError:
        return statement.split()


def aws_cli_arguments(tokens: list[str]) -> list[str] | None:
    """Arguments to the `aws` CLI, or None when this is not an `aws` invocation.

    The check is on the executable's basename being exactly `aws`. `aws-netpath`,
    `./bin/aws-netpath`, and `awslogs` are all different programs and pass.
    """
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in LEADING_KEYWORDS:
            index += 1
            continue
        # Environment assignment prefix: FOO=bar aws ...
        if "=" in token and not token.startswith("-") and "/" not in token.split("=", 1)[0]:
            index += 1
            continue
        if os.path.basename(token) in WRAPPERS:
            index += 1
            continue
        break

    if index >= len(tokens):
        return None
    if os.path.basename(tokens[index]) != "aws":
        return None
    return tokens[index + 1 :]


def is_mutating(arguments: list[str]) -> bool:
    words = [token for token in arguments if not token.startswith("-")]
    if len(words) < 2:
        # `aws`, `aws help`, `aws ec2` on their own do nothing.
        return False

    service, operation = words[0].lower(), words[1].lower()

    if service in {"s3", "s3api"} and operation in READ_ONLY_S3_SUBCOMMANDS:
        return False
    if service == "sts" and operation.startswith("get"):
        return False
    if operation.split("-", 1)[0] in READ_ONLY_VERBS:
        return False
    return True


def main() -> int:
    if os.environ.get(ALLOW_ENV) == "1":
        return 0

    raw = sys.stdin.read()
    if not raw.strip():
        return 0

    for command in candidate_commands(raw):
        for statement in statements(command):
            arguments = aws_cli_arguments(tokenise(statement))
            if arguments is None:
                continue
            if not is_mutating(arguments):
                continue
            sys.stderr.write(
                "Blocked: mutating `aws` CLI call.\n"
                f"  {statement}\n"
                "This project is read-only by construction (README, \"Read-only by\n"
                "construction\"): it changes no AWS resource and no host state, and\n"
                "enforcement is an explicit action allowlist rather than a convention.\n"
                "A write from a shell tool sits outside that allowlist.\n"
                "\n"
                "Read-only calls pass: describe-* / list-* / get-* / search-* /\n"
                "`s3 ls` / `sts get-caller-identity`.\n"
                "The project's own binary is never blocked here — `aws-netpath collect`,\n"
                "`query`, `diagnose`, and `verify` are a different executable.\n"
                f"To run a write deliberately, the operator sets {ALLOW_ENV}=1.\n"
            )
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
