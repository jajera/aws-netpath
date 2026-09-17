#!/usr/bin/env bash
#
# Shared target resolution for the save-time hooks.
#
# Why this file exists: the legacy `*.kiro.hook` format substituted ${file} into
# the command, so a save-time script simply received the edited path as $1. The
# v1 format does not substitute anything — a `command` action gets the session
# JSON on STDIN instead. Migrating the ${file} placeholder across verbatim would
# have passed the literal four-character string "${file}" and every save would
# have linted a path that does not exist, silently and successfully.
#
# So the target is resolved in three descending steps:
#
#   1. an explicit path as $1     — how a human runs the script, and how it is tested
#   2. a path found in the STDIN payload — the actual hook path, when the payload carries one
#   3. the git-dirty set          — a fallback that is always *something* useful
#
# Step 2 is written defensively on purpose. The payload schema for PostFileSave
# is not documented, so rather than binding to one key name this scans the whole
# object for any string that looks like a path of the right kind, at any depth,
# and tolerates a file:// URI. If the payload turns out to carry the path under a
# key nobody guessed, step 3 still keeps the hook honest.
#
# Sourced, not executed:
#   source "$(dirname "${BASH_SOURCE[0]}")/hook-target.sh"
#   readarray -t out < <(hook_resolve '\.go$' "${1:-}")
#   source_kind="${out[0]#source=}"     # arg | stdin | dirty | none
#   files=("${out[@]:1}")
#
# hook_resolve reports which step won on its first output line rather than in a
# variable, because callers read it through process substitution and a variable
# set in that subshell would not survive.

# hook_repo_root — absolute path to the repository root.
hook_repo_root() {
  (cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
}

# hook_relativise PATH ROOT — strip a leading repo root and any file:// scheme,
# so the go tool's ./pkg syntax works whichever form the payload used.
hook_relativise() {
  local p="$1" root="$2"
  p="${p#file://}"
  case "$p" in
    "$root"/*) p="${p#"$root"/}" ;;
  esac
  printf '%s\n' "$p"
}

# hook_payload_paths EXT_REGEX — read a JSON payload on STDIN and print every
# string value that plausibly names a file of interest.
#
# Key names are matched loosely (file, filePath, path, uri, document, ...) and
# the search recurses through nested objects and arrays. Anything that does not
# match EXT_REGEX is discarded, which is what stops a session id or a working
# directory being mistaken for the edited file.
hook_payload_paths() {
  local ext_regex="$1"
  command -v python3 >/dev/null 2>&1 || return 0
  python3 -c '
import json, re, sys

ext = re.compile(sys.argv[1])
# Keys whose value is worth considering. Deliberately broad: the payload schema
# is not documented, and a wrong guess here costs nothing because the extension
# filter below is the real gate.
keyish = re.compile(r"(file|path|uri|url|document|target|name)", re.I)

raw = sys.stdin.read()
if not raw.strip():
    sys.exit(0)
try:
    data = json.loads(raw)
except Exception:
    # Not JSON, or truncated. Fall back to pulling quoted strings out of the
    # text so a slightly different payload shape still resolves.
    found = [s for s in re.findall(r"\"([^\"]+)\"", raw) if ext.search(s)]
    for s in dict.fromkeys(found):
        print(s)
    sys.exit(0)

out = []

def walk(node, key_hint=""):
    if isinstance(node, dict):
        for k, v in node.items():
            walk(v, k)
    elif isinstance(node, list):
        for v in node:
            walk(v, key_hint)
    elif isinstance(node, str):
        if ext.search(node.strip()) and (keyish.search(key_hint) or not key_hint):
            out.append(node.strip())

walk(data)
for s in dict.fromkeys(out):
    print(s)
' "$ext_regex" 2>/dev/null
}

# hook_dirty_paths EXT_REGEX — print matching paths from git status --porcelain.
#
# Handles the rename form (`R  old -> new`) by taking the destination, and skips
# deletions, since there is nothing left on disk to lint.
hook_dirty_paths() {
  local ext_regex="$1"
  command -v git >/dev/null 2>&1 || return 0
  git status --porcelain 2>/dev/null | while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    local status="${entry:0:2}" path="${entry:3}"
    [[ "$status" == *D* ]] && continue
    # Rename or copy: the interesting half is the destination.
    if [[ "$path" == *" -> "* ]]; then
      path="${path#* -> }"
    fi
    # Porcelain quotes paths containing unusual characters.
    path="${path%\"}"
    path="${path#\"}"
    [[ -f "$path" ]] || continue
    if [[ "$path" =~ $ext_regex ]]; then
      printf '%s\n' "$path"
    fi
  done
}

# hook_resolve EXT_REGEX [EXPLICIT] — print `source=<kind>` followed by the
# resolved repo-relative targets, one per line.
#
# Must be called from the repo root (the callers cd there first).
hook_resolve() {
  local ext_regex="$1" explicit="${2:-}"
  local root
  root="$(hook_repo_root)"

  # 1. Explicit argument. A literal ${file} means a legacy command line survived
  #    somewhere; treat it as absent rather than as a filename.
  if [[ -n "$explicit" && "$explicit" != '${file}' ]]; then
    echo "source=arg"
    hook_relativise "$explicit" "$root"
    return 0
  fi

  # 2. STDIN payload. Guarded on STDIN not being a terminal so an interactive
  #    run does not block waiting for input that will never come.
  if [[ ! -t 0 ]]; then
    local payload=""
    # -d '' reads to EOF; -t 1 stops a hook hanging on a stream left open.
    IFS= read -r -d '' -t 1 payload || true
    if [[ -n "${payload// /}" ]]; then
      local -a found=()
      readarray -t found < <(printf '%s' "$payload" | hook_payload_paths "$ext_regex")
      local -a kept=()
      local p rel
      for p in "${found[@]}"; do
        [[ -z "$p" ]] && continue
        rel="$(hook_relativise "$p" "$root")"
        [[ -f "$rel" ]] || continue
        kept+=("$rel")
      done
      if (( ${#kept[@]} > 0 )); then
        echo "source=stdin"
        printf '%s\n' "${kept[@]}"
        return 0
      fi
    fi
  fi

  # 3. Dirty set.
  local -a dirty=()
  readarray -t dirty < <(hook_dirty_paths "$ext_regex")
  if (( ${#dirty[@]} > 0 )); then
    echo "source=dirty"
    printf '%s\n' "${dirty[@]}"
    return 0
  fi

  echo "source=none"
  return 0
}

# hook_cap N ITEM... — print at most N items. The caller compares the count it
# gets back against the count it passed in to learn how many were dropped, for
# the same subshell reason hook_resolve prints its source rather than exporting it.
#
# The cap matters only for the dirty fallback, and only until the working tree is
# committed: right now this repository has ~130 uncommitted files spread across
# nearly every package, so an uncapped dirty run would lint the whole module on
# every single save — several seconds, every time, which is how a hook gets
# disabled. Once the pending work is committed the dirty set is a handful of
# files and the cap never engages.
hook_cap() {
  local n="$1"
  shift
  local i=0
  local item
  for item in "$@"; do
    (( i >= n )) && break
    printf '%s\n' "$item"
    i=$((i + 1))
  done
}
