#!/usr/bin/env python3
"""Refuse to stage or commit a collected snapshot.

A snapshot written by `aws-netpath collect` is an unsanitised model of a real
network: VPC and subnet CIDRs, route tables, security group rules, firewall
policy, instance and ENI identifiers. Nothing in this tool redacts one — the
protection is policy, not sanitisation (see the comment block in .gitignore).

`.gitignore` covers `snapshot*.json` and `/snapshots/`, but two things defeat it:

    git add -f snapshots/prod.json          # force overrides the ignore rule
    aws-netpath collect --output net.json   # a name no ignore pattern matches

So this guard checks the git command itself. Two independent tests per path:

  1. the path *looks* like a snapshot — named snapshot*.json, or living under a
     snapshots/ directory; or
  2. the file exists on disk and its content *is* a snapshot: the top-level
     schema_version and captured_at keys the collector writes. This catches the
     arbitrarily-named case that no filename pattern can.

Hand-written fixtures use documentation ranges only, so they are allowlisted and
stay committable.

Wired as a Kiro PreToolUse hook scoped to shell tools. Exit code 2 blocks the tool
call and returns stderr to the agent (https://kiro.dev/docs/hooks/).

Deliberately narrow: only git staging and committing is blocked. Mentioning a
snapshot path in prose, in a commit message, or as an --output flag to
aws-netpath itself is not staging it, and passes through.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import sys

# Strings longer than this are treated as file content, not a command line.
MAX_COMMAND_CHARS = 2000

# The git subcommands that put a file into the index or a commit. `git rm` is
# deliberately absent: removing an accidentally-tracked snapshot is the fix, not
# the problem, and blocking `git rm --cached` would block the remedy.
STAGING_SUBCOMMANDS = frozenset({"add", "commit", "stash"})

FORCE_FLAGS = frozenset({"-f", "--force"})

# git's own options, before the subcommand, whose following token is a value.
GIT_GLOBAL_VALUE_FLAGS = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
)

# Long flags whose following token is a value, not a path. Without this,
# `git commit --message "add snapshot.json"` would look like it names a snapshot.
LONG_VALUE_FLAGS = frozenset(
    {
        "--message",
        "--file",
        "--reuse-message",
        "--reedit-message",
        "--author",
        "--date",
        "--pathspec-from-file",
        "--chmod",
        "--squash",
        "--fixup",
        "--cleanup",
        "--gpg-sign",
    }
)

# Short flags that take a value, which may be attached (-mmsg) or separate (-m msg).
SHORT_VALUE_LETTERS = frozenset({"m", "F", "C", "c"})

# Tracked fixtures: hand-written, documentation ranges only, safe to commit.
FIXTURE_ALLOWLIST = (
    "internal/query/testdata/*.json",
    "internal/cli/testdata/*.json",
    "internal/format/testdata/*",
    "examples/*.json",
)

# A snapshot filename, by convention.
SNAPSHOT_NAME = re.compile(r"^[-_a-z0-9.]*snapshot[-_a-z0-9.]*\.json$", re.IGNORECASE)

# Top-level keys the collector always writes. Both must be present, so an
# unrelated JSON file that happens to carry a captured_at field is not caught.
SNAPSHOT_CONTENT_MARKERS = ('"schema_version"', '"captured_at"')

CONTENT_SNIFF_BYTES = 8192

# Statement separators. A guard that only read the start of the string would miss
# `cd /tmp && git add snapshots/x.json`.
STATEMENT_SPLIT = re.compile(r"\|\||&&|[;&|\n]|\$\(|`")


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
        if 0 < len(text) <= MAX_COMMAND_CHARS and "git" in text
    ]


def statements(command: str) -> list[str]:
    return [part.strip() for part in STATEMENT_SPLIT.split(command) if part.strip()]


def tokenise(statement: str) -> list[str]:
    try:
        return shlex.split(statement)
    except ValueError:
        # Unbalanced quotes: fall back to whitespace splitting rather than let the
        # guard silently pass a command it could not read.
        return statement.split()


def _skip_git_globals(tokens: list[str], index: int) -> tuple[int, str | None]:
    """Advance past git's own options and return the subcommand."""
    while index < len(tokens):
        token = tokens[index]
        if token in GIT_GLOBAL_VALUE_FLAGS:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return index + 1, token
    return index, None


def _value_flag_span(token: str, subcommand: str) -> tuple[int, bool]:
    """Tokens this flag consumes, and whether it requested force."""
    forced = False
    if token in FORCE_FLAGS:
        forced = True
    if token.startswith("--"):
        if token in LONG_VALUE_FLAGS:
            return 2, forced
        return 1, forced
    letters = token[1:]
    if "f" in letters and subcommand == "add":
        forced = True
    for position, letter in enumerate(letters):
        if letter in SHORT_VALUE_LETTERS:
            # Last character means the value is the next token; otherwise attached.
            return (2 if position == len(letters) - 1 else 1), forced
    return 1, forced


def git_staging_call(tokens: list[str]) -> tuple[str, list[str], bool] | None:
    """Return (subcommand, path arguments, forced) for a git staging call.

    None when the statement is not one. Environment prefixes (`FOO=bar git ...`)
    and absolute paths (`/usr/bin/git`) are handled; anything else is not git.
    """
    index = 0
    while (
        index < len(tokens)
        and "=" in tokens[index]
        and not tokens[index].startswith("-")
        and "/" not in tokens[index].split("=", 1)[0]
    ):
        index += 1  # environment assignment prefix
    if index >= len(tokens) or os.path.basename(tokens[index]) != "git":
        return None

    index, subcommand = _skip_git_globals(tokens, index + 1)
    if subcommand not in STAGING_SUBCOMMANDS:
        return None

    # `git stash` only stages with push/save; `git stash list` does not.
    if subcommand == "stash":
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1
        if index >= len(tokens) or tokens[index] not in {"push", "save"}:
            return None
        index += 1

    paths: list[str] = []
    forced = False
    after_double_dash = False
    while index < len(tokens):
        token = tokens[index]
        if token == "--" and not after_double_dash:
            after_double_dash = True
            index += 1
            continue
        if not after_double_dash and token.startswith("-") and token != "-":
            span, flag_forced = _value_flag_span(token, subcommand)
            forced = forced or flag_forced
            index += span
            continue
        paths.append(token)
        index += 1

    return subcommand, paths, forced


def allowlisted(path: str) -> bool:
    normalised = path.lstrip("./")
    return any(fnmatch.fnmatch(normalised, pattern) for pattern in FIXTURE_ALLOWLIST)


def looks_like_snapshot_path(path: str) -> bool:
    cleaned = path.replace("\\", "/").rstrip("/")
    if SNAPSHOT_NAME.match(os.path.basename(cleaned)):
        return True
    parts = [part for part in cleaned.split("/") if part not in {"", ".", ".."}]
    return "snapshots" in parts


def is_snapshot_content(path: str) -> bool:
    """True when the file on disk carries the collector's top-level keys."""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(CONTENT_SNIFF_BYTES)
    except OSError:
        return False
    return all(marker in head for marker in SNAPSHOT_CONTENT_MARKERS)


def refuse(subcommand: str, path: str, forced: bool, reason: str) -> int:
    forced_note = (
        "  note:   this used --force, which overrides the .gitignore rule that\n"
        "          would otherwise have caught it.\n"
        if forced
        else ""
    )
    sys.stderr.write(
        f"Blocked: `git {subcommand}` names what looks like a collected snapshot.\n"
        f"  path:   {path}\n"
        f"  reason: {reason}\n"
        f"{forced_note}"
        "A snapshot is an unsanitised model of a real network — CIDRs, subnet\n"
        "layouts, security group rules, firewall policy, instance ids. Nothing in\n"
        "this tool redacts one, so it must never enter git history.\n"
        "\n"
        "Safe alternative:\n"
        "  - keep snapshots under snapshots/ (git-ignored) and leave them untracked;\n"
        "  - to commit a test case, hand-write a fixture under internal/*/testdata/\n"
        "    using documentation ranges only (RFC 5737 / RFC 3849), which is what the\n"
        "    existing fixtures do and what ./scripts/sanitise-gate.sh enforces.\n"
    )
    return 2


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        return 0

    for command in candidate_commands(raw):
        for statement in statements(command):
            call = git_staging_call(tokenise(statement))
            if call is None:
                continue
            subcommand, paths, forced = call
            for path in paths:
                if allowlisted(path):
                    continue
                if looks_like_snapshot_path(path):
                    return refuse(
                        subcommand,
                        path,
                        forced,
                        "the path is named or located like a collected snapshot",
                    )
                if is_snapshot_content(path):
                    return refuse(
                        subcommand,
                        path,
                        forced,
                        "the file on disk has a snapshot's schema_version and captured_at keys",
                    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
