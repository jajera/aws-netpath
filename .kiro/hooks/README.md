# Hooks

Kiro agent hooks ([reference](https://kiro.dev/docs/hooks/)). All five are the **v1** shape:
`version: "v1"` with a `hooks` array, a PascalCase `trigger`, and a `matcher` that is a **regex** —
not a glob list. For `PreToolUse` the matcher is tested against the tool name, for `PostFileSave`
against the saved file's path. A `PreToolUse` hook receives the tool-call JSON on STDIN and can
**block** the call by exiting 2, which returns its stderr to the agent.

| File                         | Trigger         | Blocks | Default | Purpose                                                                     |
| ---------------------------- | --------------- | ------ | ------- | --------------------------------------------------------------------------- |
| `guard-snapshot-commit.json` | `PreToolUse`    | yes    | enabled | Refuses `git add`/`commit`/`stash push` naming a collected snapshot.         |
| `guard-aws-mutations.json`   | `PreToolUse`    | yes    | enabled | Refuses mutating `aws` CLI calls; the project's own binary is never matched. |
| `go-check-on-save.json`      | `PostFileSave`  | no     | enabled | gofmt, vet, and golangci-lint on the saved file's package only.              |
| `workflow-lint-on-save.json` | `PostFileSave`  | no     | enabled | actionlint and yamllint on a saved workflow or lint config.                  |
| `verify-on-stop.json`        | `Stop`          | no     | enabled | The full gate set once per turn: sanitise, build, vet, gofmt, lint, test.    |

## `${file}` is not available under v1

The legacy `*.kiro.hook` format substituted `${file}` into the command, so a save-time script just
received the edited path as `$1`. v1 substitutes nothing: a `command` action gets the session JSON on
STDIN. Carrying `${file}` across would have passed the literal seven-character string and every save
would have linted a path that does not exist — silently, and exiting 0.

So `go-check.sh` and `workflow-lint.sh` resolve their target through `hook-target.sh`, in three
descending steps:

1. **an explicit path as `$1`** — how a human runs them, and how the manual tests below work;
2. **a path found in the STDIN payload** — scanned defensively, because the `PostFileSave` payload
   schema is not documented: any string at any depth under a plausibly-named key (`filePath`, `file`,
   `path`, `uri`, …), `file://` stripped, kept only if its extension matches what the hook cares
   about;
3. **the git-dirty set** — derived from `git status --porcelain` when the first two yield nothing.

Step 3 is deduplicated to package directories and capped at 10 targets, with a note when the cap
engages. The cap is not arbitrary: while the initial implementation sits uncommitted this tree has
~130 dirty files across nearly every package, so an uncapped fallback would lint the whole module on
every save. After that commit the dirty set is a handful of files and the cap never fires.

The two save-time hooks are advisory by design — they print findings and exit 0. A hook that fires
while a function is half-written would otherwise fail on every save, and a hook that fails on every
save gets disabled. `verify.sh` is the gate that exits non-zero, and it runs once a turn rather than
once a file.

The Go tools live at `$(go env GOPATH)/bin`, which is not necessarily on the hook process's PATH, so
each script adds it. Every script skips cleanly with a one-line note when a tool is absent, rather
than reporting a finding it could not actually check.

## guard-snapshot-commit

The highest-value guard in the repository. A snapshot written by `aws-netpath collect` is an
unsanitised model of a real network: VPC and subnet CIDRs, route tables, security group rules,
firewall policy, instance and ENI identifiers. Nothing in the tool redacts one — the protection is
policy, not sanitisation, which is why `.gitignore` carries the comment block it does.

`.gitignore` covers `snapshot*.json` and `/snapshots/`, and two things defeat that:

```bash
git add -f snapshots/prod.json          # --force overrides the ignore rule
aws-netpath collect --output net.json   # a name no ignore pattern matches
```

So the guard checks the git command. Each path argument fails on either of two independent tests:

1. the path *looks* like a snapshot — named `snapshot*.json`, or living under a `snapshots/`
   directory; or
2. the file exists on disk and its content *is* a snapshot: the top-level `schema_version` and
   `captured_at` keys the collector writes. This catches the arbitrarily-named case that no filename
   pattern can.

Deliberately narrow, so it does not get in the way:

- only `git add`, `git commit`, and `git stash push`/`save` are checked. Naming a snapshot in prose,
  in a commit message, or as an `--output` flag to `aws-netpath` itself is not staging it.
- `-m`/`--message` and friends have their value skipped, so
  `git commit -m "add snapshot.json"` passes.
- `git rm --cached snapshots/x.json` passes: removing an accidentally-tracked snapshot is the
  remedy, not the problem.
- these fixtures stay committable — they are hand-written and use documentation ranges only:
  `internal/query/testdata/*.json`, `internal/cli/testdata/*.json`, `internal/format/testdata/*`,
  `examples/*.json`.
- strings longer than 2000 characters are ignored as file content rather than command lines.

There is no escape hatch. To commit a test case, hand-write a fixture under `internal/*/testdata/`
using documentation ranges (RFC 5737 / RFC 3849), which is what `./scripts/sanitise-gate.sh`
enforces anyway.

Test it without Kiro:

```bash
h=.kiro/hooks/guard-snapshot-commit.py
echo '{"command":"git add snapshots/snapshot.json"}'                        | python3 $h; echo "exit=$?"  # 2
echo '{"command":"git add -f snapshots/prod.json"}'                         | python3 $h; echo "exit=$?"  # 2
echo '{"command":"git stash push snapshots/a.json"}'                        | python3 $h; echo "exit=$?"  # 2
echo '{"command":"git commit -m \"add snapshot.json\""}'                    | python3 $h; echo "exit=$?"  # 0
echo '{"command":"git add internal/query/testdata/same-vpc-permitted.json"}'| python3 $h; echo "exit=$?"  # 0
echo '{"command":"git add README.md"}'                                      | python3 $h; echo "exit=$?"  # 0
echo '{"command":"./bin/aws-netpath collect --output snapshots/snap.json"}'  | python3 $h; echo "exit=$?"  # 0
```

## guard-aws-mutations

"Read-only by construction" is a documented guarantee of this project: nothing here changes an AWS
resource or host state, and enforcement is an explicit allowlist of API actions in
`internal/guardrail` rather than a convention. A mutating `aws` CLI call from a shell tool sits
outside that allowlist and contradicts the guarantee.

- read-only verbs pass: `describe-*`, `list-*`, `get-*`, `search-*`, `head-*`, `s3 ls`,
  `sts get-caller-identity`. Anything else on an `aws` invocation is treated as mutating — refusal is
  the default, the same stance `internal/guardrail` takes.
- **the project's own binary is never matched.** `aws-netpath collect|query|diagnose|test|firewall|`
  `compare|diff|verify` is a different executable from the `aws` CLI, and `verify` legitimately
  creates a Reachability Analyzer analysis through the SDK. The check is on the executable's
  *basename being exactly* `aws`, never on a command containing the substring "aws".
- wrappers are seen through: `sudo aws iam create-role` is blocked.
- statement separators are seen through: `cd /tmp && aws ec2 run-instances` is blocked.
- strings longer than 2000 characters are ignored as file content, so a spec or README quoting
  `aws ec2 create-vpc` is documentation, not an invocation.

Opt in for a deliberate write:

```bash
export AWS_NETPATH_ALLOW_AWS_WRITE=1
```

Test it without Kiro:

```bash
h=.kiro/hooks/guard-aws-mutations.py
echo '{"command":"aws ec2 create-vpc --cidr-block 10.0.0.0/16"}'    | python3 $h; echo "exit=$?"  # 2
echo '{"command":"sudo aws iam create-role --role-name r"}'         | python3 $h; echo "exit=$?"  # 2
echo '{"command":"aws s3 cp a s3://b/c"}'                           | python3 $h; echo "exit=$?"  # 2
echo '{"command":"aws ec2 describe-vpcs"}'                          | python3 $h; echo "exit=$?"  # 0
echo '{"command":"aws s3 ls"}'                                      | python3 $h; echo "exit=$?"  # 0
echo '{"command":"aws sts get-caller-identity"}'                    | python3 $h; echo "exit=$?"  # 0
echo '{"command":"./bin/aws-netpath verify --snapshot x.json --from a --to b"}' | python3 $h; echo "exit=$?"  # 0
AWS_NETPATH_ALLOW_AWS_WRITE=1 \
  sh -c 'echo "{\"command\":\"aws ec2 create-vpc --cidr-block 10.0.0.0/16\"}" | python3 '"$h"; echo "exit=$?"  # 0
```

## go-check

`bash .kiro/hooks/go-check.sh <file>` — scoped to the edited file's package directory, not `./...`,
so a save costs a fraction of a second rather than the several the whole module would take. Runs
`gofmt -l` on the file, then `go vet` and `golangci-lint run` on `./<package dir>`. Absolute paths
are relativised to the repo root first, since Kiro may hand over either form.

```bash
bash .kiro/hooks/go-check.sh internal/cli/collect.go
```

## workflow-lint

`bash .kiro/hooks/workflow-lint.sh <file>` — `actionlint` when the file is a workflow (it understands
the Actions schema, expression syntax, and the shell inside `run:` blocks, none of which yamllint can
see), then `yamllint -c .yamllint`, using the repo's own config so the hook cannot drift from what
the `yaml-lint` workflow enforces. Without it, a malformed workflow or a `.golangci.yml` that no
longer parses is only discovered on push.

```bash
bash .kiro/hooks/workflow-lint.sh .github/workflows/release.yml
```

## verify

`bash .kiro/hooks/verify.sh` — the same gates CI runs, in cost order, one `PASS`/`FAIL`/`SKIP` line
each plus a summary:

`./scripts/sanitise-gate.sh` → `go build ./...` → `go vet ./...` → `gofmt -l .` (must be empty) →
`golangci-lint run` → `go test ./...`

Runs in roughly 1.5–2 seconds on a warm cache, which is what makes an every-turn hook tolerable.
Output is terse for the same reason: failure detail is printed only for the gates that failed, and
truncated to 15 lines, with `go test`'s per-package `ok` lines dropped so the one failure is not
buried. Exits 1 when a gate genuinely failed, so the agent notices. A skipped gate is never reported
as a pass — the summary says so and the closing line stops claiming the tree is green.
