# Implementation Plan: aws-netpath

## Overview

Absorb the existing `netprobe` Go codebase into this repository, then extend it with host-layer
probing, symptom classification, verdict correlation, baseline comparison, snapshot diffing, declared
flow testing, and an MCP server.

Ordering: migration first behind a green inherited test suite, then shared operations extraction, then
pure-logic additions, then integrations, then interfaces and docs. The migration is a gate — no new
capability begins until `go test ./...` passes on the imported tree.

## Tasks

- [x] 1. Absorb the netprobe codebase
  - [x] 1.1 Import the tree and initialise version control
    - Copy `cmd/`, `internal/`, `examples/`, `go.mod`, `go.sum` from `~/workspace/netprobe`
    - Preserve `examples/double-inspection.json` and the query testdata as regression fixtures
    - Do not import `bin/`, `snapshot.json`, or `snapshot-field-pulp.json` (local artefacts, may
      contain environment detail)
    - Add `.gitignore` covering `bin/`, `*.tfstate`, and local snapshots
    - _Requirements: 16.1_
  - [x] 1.2 Rename the module and command
    - Module path `github.com/netprobe/netprobe` → `github.com/jajera/aws-netpath`
    - `cmd/netprobe` → `cmd/aws-netpath`
    - Update all internal imports
    - _Requirements: 16.1_
  - [x] 1.3 Tidy dependencies
    - Promote `aws-sdk-go-v2` requirements from `// indirect` to direct where used
    - `go mod tidy`
    - _Requirements: 16.1_
  - [x] 1.4 Sanitise all inherited content for public release
    - Replace real account IDs in `examples/*.yaml` with placeholders (`111122223333`, `444455556666`)
    - Replace real profile names with neutral ones (`account-a`, `account-b`, `network-hub`)
    - Replace routable address ranges in README, examples, and `internal/query/testdata/` with RFC 5737
      documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 1918 ranges
    - Audit and sanitise test files carrying environment data: `internal/verify/*_test.go`,
      `internal/query/sg_test.go`, `internal/config/config_test.go`, `internal/nfw/*_test.go`
    - Rename `internal/query/testdata/prod-blocked.json` to a neutral fixture name
    - Grep gate: no match for real org names, account IDs, or routable ranges anywhere in the tree
    - _Requirements: 17.1, 17.2, 17.4_
  - [x] 1.5 Remove environment coupling from logic and defaults
    - No hardcoded region, account, profile, or naming convention in any code path
    - Example configuration demonstrates shape with placeholders only
    - _Requirements: 17.3, 17.4_
  - [x] 1.6 Verify the inherited suite is green after sanitisation
    - `go test ./...`, `go vet ./...`, `gofmt -l .` all clean
    - Fixture renames and value substitutions must not change any assertion outcome
    - This is the gate for every later task
    - _Requirements: 3.5_
  - [x] 1.7 Add Snapshot schema version and collection timestamp
    - Version constant, written on collect, validated on load
    - Error naming expected and found versions on mismatch
    - _Requirements: 2.6, 2.7_

- [x] 2. Extract shared operations
  - [x] 2.1 Create `internal/ops` and move command bodies from `internal/cli`
    - `Collect`, `Query`, `Firewall`, `Verify` as callable operations returning typed results
    - `internal/cli` retains flag parsing and exit-code mapping only
    - _Requirements: 16.4_
  - [x] 2.2 Confirm CLI behaviour is unchanged after extraction
    - Existing command output and exit codes identical
    - _Requirements: 16.6_

- [x] 3. Verdict model extension
  - [x] 3.1 Add `LayerVerdict`, `Layer`, `Citation`, `LayerResult`, `Verdict` to `internal/model`
    - `LayerResult.Reason` required when verdict is `abstain`
    - `Verdict.Authoritative` computed from conclusion-affecting Abstentions
    - _Requirements: cross-cutting 1, 2, 14.1, 14.6_
  - [x] 3.2 Map existing `internal/nfw` abstentions onto `VerdictAbstain`
    - Preserve the construct name in `Reason`
    - _Requirements: 5.4, 5.5_

- [x] 4. Guardrails
  - [x] 4.1 Implement `internal/guardrail`
    - `allowedAWSActions` and `allowedHostCommands` maps per design
    - `ValidateAction`, `ValidateHostCommand`, metacharacter rejection
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_
  - [x] 4.2 Tests
    - Allowlists are exact-match only
    - Arguments containing shell metacharacters are always rejected
    - Host command validation runs before any dispatch path
    - _Requirements: 15.1, 15.2, 15.3_

- [x] 5. Symptom classifier (pure logic)
  - [x] 5.1 Implement `internal/symptom`
    - Map each Symptom to candidate Layers per the requirement 9.1 table
    - Return candidate Layers plus a check order
    - Order host Layers before cloud Layers for actively rejected Symptoms
    - _Requirements: 9.1, 9.2, 9.3, 9.5_
  - [x] 5.2 Table-driven tests
    - Every Symptom yields at least one candidate Layer
    - Active-rejection Symptoms always order host Layers first
    - Silent-discard and active-rejection Symptoms produce different orders
    - _Requirements: 9.1, 9.2_

- [x] 6. Correlator (pure logic)
  - [x] 6.1 Implement `internal/correlate`
    - Verdict precedence: earliest blocking Layer in flow order is primary
    - Additional blockers listed after the primary
    - Reconcile findings against Symptom; record contradictions without resolving them
    - Set `Authoritative = false` when an Abstention affects the conclusion
    - _Requirements: 7.4, 9.4, 14.1, 14.6, cross-cutting 1, 6_
  - [x] 6.2 Tests
    - Precedence always selects the earliest blocking Layer
    - An Abstention affecting the conclusion never yields an authoritative verdict
    - `ABSTAIN` is never aggregated as `PASS`
    - Cloud Layers pass plus host firewall blocked yields `HOST_FIREWALL` primary
    - _Requirements: 14.1, 14.6, cross-cutting 1_

- [x] 7. Complete security group evaluation
  - [x] 7.1 Collect elastic network interfaces
    - Attribute security groups to endpoints
    - _Requirements: 2.2_
  - [x] 7.2 Evaluate source and destination security groups in the path walk
    - Remove the current v1 limitation
    - _Requirements: 4.3_
  - [x] 7.3 Tests covering an allowed and a blocked security group path
    - _Requirements: 4.3_

- [x] 8. Return path evaluation
  - [x] 8.1 Evaluate the reverse direction as a distinct Flow
    - _Requirements: 7.1_
  - [x] 8.2 Compare next hops and detect asymmetry, citing both
    - _Requirements: 7.2_
  - [x] 8.3 Flag asymmetry through a stateful component as probable stall cause
    - _Requirements: 7.3_
  - [x] 8.4 Report a blocked return direction as primary blocker
    - _Requirements: 7.4_
  - [x] 8.5 Tests for symmetric and asymmetric topologies
    - _Requirements: 7.2_

- [x] 9. Host prober
  - [x] 9.1 SSM runner enforcing the command allowlist before dispatch
    - Fixed templates, argument lists, validated substitution
    - _Requirements: 8.7, 15.5_
  - [x] 9.2 Listener check and `ss -tlnp` parser
    - _Requirements: 8.1, 8.5_
  - [x] 9.3 firewalld rich rule and service parsers
    - Match source by network containment, not string equality
    - _Requirements: 8.2, 8.3, 8.4_
  - [x] 9.4 Local route and path MTU checks
    - _Requirements: 8.1_
  - [x] 9.5 Abstain when SSM is unavailable or the instance is unmanaged
    - _Requirements: 8.6_
  - [x] 9.6 Parser fixture tests
    - Allowlist covering the source by containment
    - Allowlist omitting the source
    - Absent listener
    - _Requirements: 8.3, 8.4, 8.5_

- [x] 10. Diagnose operation
  - [x] 10.1 Implement `ops.Diagnose` in the documented stage order
    - Config, classify, resolve, cloud layers, return path, host layers, correlate, format
    - _Requirements: 9.5, 14.1_
  - [x] 10.2 Host stage SHALL run even when cloud layers report permitted
    - _Requirements: 8.1_
  - [x] 10.3 Endpoint resolution from the Snapshot
    - Ambiguity halts with candidates listed; no match reports available scopes
    - External CIDRs treated as ordinary nodes
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 11. Comparator
  - [x] 11.1 Implement `internal/compare`
    - Evaluate failing and reference paths, emit differences only
    - _Requirements: 10.1, 10.2_
  - [x] 11.2 Direct to host Layers when cloud Layers match but behaviour differs
    - _Requirements: 10.3_
  - [x] 11.3 Report incomplete comparison when a Layer abstains on one side
    - _Requirements: 10.4_
  - [x] 11.4 Diff output tests
    - _Requirements: 10.2_

- [x] 12. Formatter
  - [x] 12.1 Implement `internal/format`
    - Text renderer preserving the inherited rule-citing style
    - Three sections: blocking Layer with Citations, cleared Layers, Abstentions with reasons
    - _Requirements: 14.2, 14.3, 14.4_
  - [x] 12.2 Markdown renderer with row truncation stated
    - _Requirements: 14.5_
  - [x] 12.3 Stable JSON renderer
    - _Requirements: 14.3, 16.5_
  - [x] 12.4 Non-authoritative banner when a verdict rests on an Abstention
    - _Requirements: 14.6_
  - [x] 12.5 Assert no credential or secret material is rendered
    - _Requirements: 14.7_

- [x] 13. Snapshot diff
  - [x] 13.1 Implement `internal/diffsnap`
    - Added, removed, modified resources grouped by type, account, region
    - _Requirements: 11.1, 11.2_
  - [x] 13.2 Report possible incompleteness on schema version mismatch
    - _Requirements: 11.3_
  - [x] 13.3 Tests
    - _Requirements: 11.1_

- [x] 14. Declared flow testing
  - [x] 14.1 Implement `internal/flowtest`
    - Parse a declared flow file with expected verdicts
    - _Requirements: 12.1_
  - [x] 14.2 Report mismatches with both verdicts and the deciding Citation
    - _Requirements: 12.2_
  - [x] 14.3 Exit `1` on any failure; report abstentions as inconclusive, never as pass
    - _Requirements: 12.3, 12.4_
  - [x] 14.4 Tests
    - _Requirements: 12.2, 12.4_

- [x] 15. Verify extensions
  - [x] 15.1 State analyser caveats in output
    - Billable; TCP over a transit gateway route table is forward-only
    - _Requirements: 13.4_
  - [x] 15.2 Report that no single analyser run covers a cross-region Flow
    - _Requirements: 13.5_
  - [x] 15.3 Report disagreement prominently, preferring neither source
    - _Requirements: 13.3_

- [x] 16. CLI
  - [x] 16.1 Add `diagnose`, `compare`, `diff`, `test` subcommands
    - _Requirements: 16.2_
  - [x] 16.2 Add `--symptom`, `--json`, `--markdown` flags
    - _Requirements: 9.1, 14.3_
  - [x] 16.3 Exit codes `0` / `1` / `2` per cross-cutting semantics
    - _Requirements: 16.6, cross-cutting 7_
  - [x] 16.4 CLI tests asserting against stable JSON output
    - _Requirements: 16.5_

- [x] 17. MCP server
  - [x] 17.1 Implement `internal/mcpserver` using the official MCP Go SDK over stdio
    - _Requirements: 16.3_
  - [x] 17.2 Register every operation as a tool with a schema
    - `collect`, `query`, `firewall`, `diagnose`, `compare`, `verify`, `diff`, `test`
    - _Requirements: 16.3, 16.4_
  - [x] 17.3 Return markdown by default for low-token consumption
    - _Requirements: 14.5_
  - [x] 17.4 Server tests
    - _Requirements: 16.3_

- [x] 18. End-to-end regression tests
  - [x] 18.1 Motivating incident
    - All cloud Layers `PASS`, firewalld allowlist missing the source CIDR
    - Expected: `HOST_FIREWALL` blocked, allowlist cited
    - _Requirements: 8.4, 14.1, 14.2_
  - [x] 18.2 Asymmetric path with `connect-then-stall`
    - Expected: `RETURN_PATH` reported, both next hops cited
    - _Requirements: 7.2, 7.3_
  - [x] 18.3 Double inspection using the inherited example
    - Expected: pass at the first firewall, drop at the second, both cited
    - _Requirements: 5.6_

- [x] 19. Documentation
  - [x] 19.1 README: collect, configure, worked example, command reference
    - _Requirements: 18.1_
  - [x] 19.2 Document the read-only guarantee and every allowlisted action and command
    - _Requirements: 18.2_
  - [x] 19.3 Document every Abstention condition and known limitation
    - _Requirements: 18.3_
  - [x] 19.4 Document prior art and differentiation
    - _Requirements: 18.5_

- [x] 20. Steering playbooks
  - [x] 20.1 `ssh-failure-triage.md`
    - Symptom-first ordering; the refused / timeout / no-route-to-host split
    - _Requirements: 18.4_
  - [x] 20.2 `service-unreachable-triage.md`
    - Listener check before policy investigation
    - _Requirements: 18.4_
  - [x] 20.3 `asymmetric-path-triage.md`
    - Return path first when the symptom is connect-then-stall
    - _Requirements: 18.4_
  - [x] 20.4 `compare-with-working-host.md`
    - Baseline comparison as a first-class workflow
    - _Requirements: 18.4, 10.1_

- [x] 21. Packaging
  - [x] 21.1 `.kiro/settings/mcp.json` registering the `aws-netpath` server
    - _Requirements: 16.3_
  - [x] 21.2 Release build producing a static binary per platform
    - _Requirements: 16.1_
