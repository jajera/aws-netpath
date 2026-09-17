# aws-netpath

Model an AWS network once, then answer reachability and diagnosis questions offline — instantly, free, with a citation for every verdict.

> **Status: engine imported, extensions in progress.** The inherited engine — flow algebra, Network
> Firewall evaluator, multi-profile `collect`, `query`, `firewall`, and `verify` — works and is tested.
> Host-layer probing, symptom classification, verdict correlation, baseline comparison, snapshot diff,
> declared flow tests, and the MCP server are built and covered by tests; host probing needs a Systems
> Manager client the CLI does not yet open, so the host layers abstain. See
> [.kiro/specs/aws-netpath](.kiro/specs/aws-netpath) for requirements, design, and the task plan.

Every address, account ID, and profile name in this repository is a placeholder. Documentation,
examples, fixtures, and tests use RFC 1918 and RFC 5737 reserved ranges and reserved documentation
account IDs only. Nothing in the tool assumes a particular region, account, profile, or naming scheme.

## Build

```bash
go build -o bin/aws-netpath ./cmd/aws-netpath
./bin/aws-netpath --help
```

One binary, no runtime dependency beyond itself. Everything except `collect` and `verify` runs with no
AWS credentials and no network access.

## Configure

A config file is optional. It earns its place as soon as regions differ per account, because the
alternative is repeating `--regions` on every invocation.

```yaml
# aws-netpath.yaml — see examples/aws-netpath.yaml for the annotated version
accounts:
  - id: "111122223333"        # optional; discovered via STS when omitted
    profile: network-hub      # required: an AWS shared-config profile
    regions:                  # required: at least one
      - us-east-1
      - us-west-2

  - id: "444455556666"
    profile: workload-prod
    regions:
      - us-east-1
```

| Field | Required | Meaning |
| --- | --- | --- |
| `accounts[].profile` | yes | AWS shared-config profile name, SSO or static credentials |
| `accounts[].regions` | yes | Regions to collect in this account |
| `accounts[].id` | no | 12-digit account number; discovered with STS `GetCallerIdentity` when omitted |
| `accounts[].assume_role` | no | Role ARN assumed *after* the profile authenticates, for CI starting in a tooling account |
| `accounts[].role_session_name` | no | Overrides the default STS session name |
| `external[]` | no | Address space that is not in AWS |

Each account is reached through **its own credential profile**. No AWS Organizations trusted access,
delegated administrator, or org-wide role is involved, so this works in an estate where you hold
credentials for several accounts and no privileged position over any of them.

At least one account with a profile and a region is required; anything less is a usage error naming the
field that failed.

### Declaring address space outside AWS

An on-premises range behind Direct Connect, or a partner network behind a VPN, is not in any collected
VPC. Declaring it makes such a destination an ordinary node in the graph rather than an unknown
address:

```yaml
external:
  - name: on-prem
    cidrs:
      - 192.168.0.0/16
    reached_via: dx-gateway
    description: On-premises estate via Direct Connect
```

Undeclared external space still works — a CIDR belonging to no collected VPC is treated as an ordinary
external node rather than an error. Routing is evaluated, destination-side policy is not, and the
report says so.

## Collect

Authenticate each profile first, then collect once:

```bash
aws sso login --profile network-hub
aws sso login --profile workload-prod

aws-netpath collect --config aws-netpath.yaml
```

Two shapes exist for the config-free case:

```bash
# Each profile crossed with each region.
aws-netpath collect --profiles network-hub,workload-prod --regions us-east-1,us-west-2

# One profile, one or more regions.
aws-netpath collect --profile network-hub --regions us-east-1,us-west-2 --output snapshots/prod.json
```

`--config` wins when given. `--profile` and `--profiles` are mutually exclusive, and both need
`--regions`.

Without `--output` the snapshot lands at `snapshots/snapshot.json`. Nothing in this tool sanitises a
snapshot — it is an unredacted model of a real network and must never be committed — so the default
writes into a directory `.gitignore` excludes wholesale, rather than relying on a filename pattern that
the first `--output prod-net.json` defeats. Missing directories in `--output` are created.

What lands in the snapshot: VPCs, subnets, route tables, security groups, NACLs, elastic network
interfaces, transit gateways, transit gateway route tables and attachments, VPC peerings, and Network
Firewall firewalls, policies, and rule groups. Interfaces matter more than they look — they are what
attributes a security group to an address, so a query can answer for an endpoint rather than for a
subnet.

Every account and region pair is collected in parallel, bounded by `--timeout` seconds per pair (`0`
disables the limit). `collect` prints the snapshot path, the number of pairs attempted, and a count per
resource type.

**Partial failures do not abort the run.** A scope or resource type that cannot be read — usually a
missing permission — is recorded in `collection_errors` inside the snapshot, the remaining accounts
still collect, and an `errors:` line appears in the summary. The exit code is `1`: incomplete, but
usable. An unreadable policy is surfaced rather than silently treated as absent, because "absent"
would read as "permits nothing" and that is a guess.

Snapshots carry a schema version and a collection timestamp. Loading a snapshot written by an
incompatible build fails with the expected and found versions rather than misreading it.

**Snapshots are sensitive.** A snapshot is a model of a real network, and nothing here attempts to
redact one. `.gitignore` keeps snapshots out of version control; they are excluded from sharing by
policy rather than by transformation.

## Worked example, end to end

The bundled snapshot `examples/double-inspection.json` is a two-region estate: a prod VPC in
`us-east-1` and an edge VPC in `us-west-2`, joined by a transit gateway peering, with a Network
Firewall inspecting traffic in each region. `us-east-1` permits `tcp/443` between the two ranges.
`us-west-2` has no matching rule and defaults to a strict drop. It stands in here for the snapshot you
would have written with `collect`, so every command below runs offline with no credentials.

```bash
go build -o bin/aws-netpath ./cmd/aws-netpath
```

### 1. Ask whether the flow gets through

```bash
./bin/aws-netpath query \
  --snapshot examples/double-inspection.json \
  --from 10.30.32.10 --to 10.30.192.10 \
  --proto tcp --port 443
```

```plaintext
flow: 10.30.32.10/32 -> 10.30.192.10/32 tcp/443

  [ALLOW] prod-app (us-east-1)
         egress permitted by sg-prod-app allow any/any to 0.0.0.0/0
  [ALLOW] prod-spoke-rt (us-east-1)
         vpc route → TGW tgw-east
  [ALLOW] tgw-attach-prod-east (us-east-1)
         entered transit gateway
  [ALLOW] trt-inspection-prod-use1 (us-east-1)
         0.0.0.0/0 → vpc-inspection-east (attachment)
  [ALLOW] vpc-inspection-prod-use1 (us-east-1)
         traffic enters inspection VPC via TGW
  [ALLOW] nfw-prod-use1 (us-east-1)
         nfr-use1-allow-east-west sid 3 (priority 6)
  [ALLOW] rtb-firewall-use1 (us-east-1)
         egress → TGW tgw-east
  [ALLOW] tgw-attach-inspection-east (us-east-1)
         re-entered transit gateway after inspection
  [ALLOW] trt-no-inspection-prod-use1 (us-east-1)
         10.30.128.0/17 → tgw-west (attachment)
  [ALLOW] tgw-attach-peering-west (us-east-1)
         cross-region peering → tgw-west
  [ALLOW] trt-inspection-prod-usw2 (us-west-2)
         0.0.0.0/0 → vpc-inspection-west (attachment)
  [ALLOW] vpc-inspection-prod-usw2 (us-west-2)
         traffic enters inspection VPC via TGW
  [DENY ] nfw-prod-usw2 (us-west-2)
         default action aws:drop_established,aws:alert_strict,aws:drop_strict

verdict: BLOCKED
```

Thirteen hops across two regions, and the one that matters is named. The flow clears the first
firewall and dies at the second. This is the failure mode that sends people to packet captures, and a
single-region analyzer cannot show it to you: a green result in `us-east-1` says nothing about
`us-west-2`.

### 2. Narrow to the policy that decided it

`firewall` skips the path walk and reports one verdict per inspection point, which is the shorter read
once you already know the traffic reaches the firewall:

```bash
./bin/aws-netpath firewall \
  --snapshot examples/double-inspection.json \
  --from 10.30.32.0/19 --to 10.30.192.0/20 \
  --proto tcp --port 443
```

```plaintext
flow: 10.30.32.0/19 -> 10.30.192.0/20 tcp/443

nfw-prod-use1 (us-east-1)
  PASS  10.30.32.0/19 -> 10.30.192.0/20 tcp/443
        via nfr-use1-allow-east-west sid 3 (priority 6)

nfw-prod-usw2 (us-west-2)
  DROP  10.30.32.0/19 -> 10.30.192.0/20 tcp/443
        via default action aws:drop_established,aws:alert_strict,aws:drop_strict

verdict: BLOCKED
```

Ask about several ports at once and the answer splits along the boundary the rules actually draw:

```bash
./bin/aws-netpath firewall \
  --snapshot examples/double-inspection.json \
  --from 10.30.32.0/19 --to 10.30.192.0/20 \
  --proto tcp --port 443,8080 --firewall use1
```

```plaintext
flow: 10.30.32.0/19 -> 10.30.192.0/20 tcp/443,8080

nfw-prod-use1 (us-east-1)
  PASS  10.30.32.0/19 -> 10.30.192.0/20 tcp/443
        via nfr-use1-allow-east-west sid 3 (priority 6)
  PASS  10.30.32.0/19 -> 10.30.192.0/20 tcp/8080
        via default action aws:drop_established,aws:alert_strict

verdict: PERMITTED
```

`--port` takes a single port, a range (`80-443`), or a list (`22,443`). `--firewall` matches on a
substring of the firewall name or ID.

### 3. Get the layered report

`diagnose` runs the same path walk and then arranges it the way an investigation reads: the blocking
layer with its citations, the layers that cleared, and the layers that could not be established.

```bash
./bin/aws-netpath diagnose \
  --snapshot examples/double-inspection.json \
  --from 10.30.32.10 --to 10.30.192.10 \
  --proto tcp --port 443
```

```plaintext
flow: 10.30.32.10/32 -> 10.30.192.10/32 tcp/443
source: 10.30.32.10, interface eni-prod-app, instance i-0aaaaaaaaaaaaaaa1, subnet subnet-prod-east-a, vpc vpc-prod-east, account 111122223333 region us-east-1
destination: 10.30.192.10, interface eni-edge-api, instance i-0bbbbbbbbbbbbbbb1, subnet subnet-edge-west-a, vpc vpc-edge-west, account 444455556666 region us-west-2
verdict: BLOCKED at firewall

blocking layer — firewall:
  [DENY ] firewall
         cited: nfw-prod-use1  firewall: nfr-use1-allow-east-west sid 3 (priority 6)
         cited: nfw-prod-usw2  firewall: default action aws:drop_established,aws:alert_strict,aws:drop_strict

cleared layers:
  [ALLOW] resolution
         cited: eni-prod-app  source 10.30.32.10 resolved to 10.30.32.10, interface eni-prod-app, instance i-0aaaaaaaaaaaaaaa1, subnet subnet-prod-east-a, vpc vpc-prod-east, account 111122223333 region us-east-1
         cited: eni-edge-api  destination 10.30.192.10 resolved to 10.30.192.10, interface eni-edge-api, instance i-0bbbbbbbbbbbbbbb1, subnet subnet-edge-west-a, vpc vpc-edge-west, account 444455556666 region us-west-2
  [ALLOW] route
         cited: prod-spoke-rt  route: vpc route → TGW tgw-east
         cited: tgw-attach-prod-east  tgw: entered transit gateway
         cited: trt-inspection-prod-use1  tgw-route: 0.0.0.0/0 → vpc-inspection-east (attachment)
         cited: vpc-inspection-prod-use1  inspection-vpc: traffic enters inspection VPC via TGW
         cited: rtb-firewall-use1  inspection-vpc: egress → TGW tgw-east
         cited: tgw-attach-inspection-east  tgw: re-entered transit gateway after inspection
         cited: trt-no-inspection-prod-use1  tgw-route: 10.30.128.0/17 → tgw-west (attachment)
         cited: tgw-attach-peering-west  tgw-peering: cross-region peering → tgw-west
         cited: trt-inspection-prod-usw2  tgw-route: 0.0.0.0/0 → vpc-inspection-west (attachment)
         cited: vpc-inspection-prod-usw2  inspection-vpc: traffic enters inspection VPC via TGW
  [ALLOW] security_group
         cited: sg-prod-app  egress allow any/any to 0.0.0.0/0

abstentions:
  [ABSTAIN] host_firewall
         host layer unverified: host command could not be delivered: the diagnose operation was given no systems manager client, so the host was not probed
  [ABSTAIN] host_listener
         host layer unverified: host command could not be delivered: the diagnose operation was given no systems manager client, so the host was not probed
  (no abstention could have changed this verdict)
note: host command could not be delivered: the diagnose operation was given no systems manager client, so the host was not probed
```

Two things to read here. The blocking layer names the rule and the priority behind each decision, so
the fix is a specific line in a specific rule group. And the host layers say they were *not checked*
rather than that they were fine — an abstention is never folded into a pass, and the report says
whether one could have changed the verdict. Here it could not: a layer that was never evaluated cannot
un-block traffic another layer was shown to drop.

Endpoints accept an address, a CIDR, an instance ID, or a `Name` tag. An input matching more than one
resource halts with every candidate listed rather than answering for the wrong one.

Add `--symptom` when you have an observed client-side error, and the layers that failure implicates
are checked first:

```bash
./bin/aws-netpath diagnose --snapshot examples/double-inspection.json \
  --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 \
  --symptom connection-refused
```

A refused connection came from a host that answered, so the host layers lead. A symptom narrows the
search rather than limiting it — every layer is still reported.

### 4. Codify it so a regression fails a build

Write down what reachability is supposed to be:

```yaml
# examples/flows.yaml
flows:
  - name: east-west https must stay permitted
    from: 10.30.32.10
    to: 10.30.192.10
    proto: tcp
    port: 443
    expect: permitted

  - name: workloads must not reach the management range over ssh
    from: 10.30.32.10
    to: 192.0.2.10
    proto: tcp
    port: 22
    expect: blocked
```

```bash
./bin/aws-netpath test --snapshot examples/double-inspection.json --flows examples/flows.yaml
```

```plaintext
verdict: FAILED: 1 of 2 declared flows did not meet the declared verdict

failures:
  [FAIL ] east-west https must stay permitted
         declared permitted, actual blocked, decided at firewall
         flow: 10.30.32.10/32 -> 10.30.192.10/32 tcp/443
         cited: nfw-prod-use1  firewall: nfr-use1-allow-east-west sid 3 (priority 6)
         cited: nfw-prod-usw2  firewall: default action aws:drop_established,aws:alert_strict,aws:drop_strict

flows that met their expected verdict:
  [PASS ] workloads must not reach the management range over ssh
  (evidence omitted: a declared flow run details the flows that did not meet their expected verdict)

inconclusive flows:
  (every declared flow was established)
note: a declared flow that did not meet its expected verdict is a failure of the declaration or of the network, and this run does not decide which
```

Exit `1`, with the deciding citation attached, so this drops into a pipeline without a wrapper. A flow
whose endpoints cannot be resolved, or that abstains, is reported as **inconclusive** — never as a
pass, and never as a failure either.

Each declared flow asserts whether traffic gets through, not which layer decided it, so a change that
moves a refusal from a security group to a firewall rule has not broken anything declared here.
`proto` is never defaulted: a declared flow with an implied protocol asserts something other than what
its author read.

### 5. Tie a breakage to a change

Keep snapshots. When something breaks, the question is usually what moved:

```bash
aws-netpath collect --config aws-netpath.yaml --output snapshot-2026-09-01.json
# ... a change lands ...
aws-netpath collect --config aws-netpath.yaml --output snapshot-2026-09-08.json

aws-netpath diff --from snapshot-2026-09-01.json --to snapshot-2026-09-08.json
```

Resources added, removed, and modified, grouped by type and by account and region. No path is walked
and no policy is evaluated, which makes this the cheapest way to find the change. Schema versions may
differ between a collection from before a change and one from after it; both are read either way, and
the report states that the comparison may be incomplete.

### 6. Cross-check the model against AWS

`verify` runs the offline query and then, where AWS can answer the same question, an AWS Reachability
Analyzer analysis, and reports both verdicts side by side. It needs credentials, so `--skip-aws`
demonstrates the shape offline:

```bash
./bin/aws-netpath verify --snapshot examples/double-inspection.json \
  --from 10.30.32.10 --to 10.30.192.10 --proto tcp --port 443 --skip-aws
```

```plaintext
flow: 10.30.32.10/32 -> 10.30.192.10/32 tcp/443
source: engine: BLOCKED (stopped at firewall nfw-prod-usw2 after 13 hops)
source: reachability analyzer: NO RESULT (skipped by request)
verdict: NOT CORROBORATED: AWS Reachability Analyzer did not return a result
!! this verdict is not corroborated: AWS Reachability Analyzer did not return a result

verdicts compared:
  [BLOCKED] engine
         stopped at firewall nfw-prod-usw2 after 13 hops
         cited: firewall nfw-prod-usw2  default action aws:drop_established,aws:alert_strict,aws:drop_strict
         cited: nfw-prod-use1  nfr-use1-allow-east-west sid 3 (priority 6)
         cited: nfw-prod-usw2  default action aws:drop_established,aws:alert_strict,aws:drop_strict
  [NO RESULT] reachability analyzer
         skipped by request
         cited: no analysis  skipped by request
  (only the engine reached a verdict, so there is nothing to compare it against)

corroborated:
  (nothing was corroborated: only one source reached a verdict)

caveats:
  [CAVEAT] analysis cost
         Reachability Analyzer analyses are billable: each run creates a network insights path and an analysis and is charged per analysis, where the offline query over the snapshot costs nothing
  [CAVEAT] forward direction only
         for TCP over a transit gateway route table, Reachability Analyzer evaluates forward traffic only: this comparison says nothing about the return direction, which is where an asymmetric path fails
  [CAVEAT] cross-region path
         no single Reachability Analyzer run covers us-east-1 to us-west-2: an analysis is scoped to one region, so no run evaluates this path end to end and two runs cannot be joined into one verdict
  (what this comparison established is narrowed by forward direction only and cross-region path)
note: AWS comparison skipped
```

The caveats are the point. This particular flow crosses a region boundary, so no single analyzer run
covers it and the comparison cannot settle anything — which the output says, rather than reporting a
same-region answer as though it covered the path. When both sources do reach a verdict and disagree,
neither is silently preferred.

## Command reference

Run `aws-netpath <command> -h` for the flags a command accepts.

| Command | Needs AWS | Purpose |
| --- | --- | --- |
| `collect` | yes | Collect AWS network state into a snapshot, one profile per account |
| `query` | no | End-to-end reachability: routes, NACLs, security groups, firewalls |
| `firewall` | no | Evaluate a flow against every firewall policy in a snapshot |
| `diagnose` | no | Layered report across cloud and host layers, symptom-first on request |
| `compare` | no | Diff a failing path against a reference path that works |
| `diff` | no | Report what changed between two snapshots |
| `test` | no | Assert a file of declared flows against a snapshot |
| `verify` | yes | Compare the model's verdict against AWS Reachability Analyzer |

Those eight are the operations, and each is also an MCP tool of the same name running the same code, so
an agent and an operator cannot be told different things about the same network. Two more commands are
interface rather than capability:

| Command | Purpose |
| --- | --- |
| `mcp` | Serve the operations to an agent over MCP on stdio |
| `version` | Print the version |

### Flags

`collect`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config` | | Path to `aws-netpath.yaml`; takes precedence over the profile flags |
| `--output` | `snapshots/snapshot.json` | Where to write the snapshot; the default directory is gitignored, and missing directories are created |
| `--profile` | | Single-account mode; needs `--regions` |
| `--profiles` | | Comma-separated profiles, each crossed with every `--regions` value |
| `--regions` | | Comma-separated regions |
| `--account` | | Optional account ID check, single `--profile` only |
| `--assume-role` | | Role ARN assumed after the profile authenticates |
| `--timeout` | `120` | Per account+region timeout in seconds; `0` means no limit |

`query`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--snapshot` | required | Path to a snapshot file |
| `--from`, `--to` | required | Source and destination IP address |
| `--proto` | `tcp` | `tcp`, `udp`, or `icmp` |
| `--port` | | Destination port, required for `tcp` and `udp` |
| `--skip-firewall` | | Evaluate routing and NACLs only |
| `--json` | | JSON output |

`firewall`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--snapshot` | required | Path to a snapshot file |
| `--from`, `--to` | required | Source and destination CIDR or address |
| `--proto` | `tcp` | `tcp`, `udp`, `icmp`, or `any` |
| `--port` | `any` | `443`, a range `80-443`, or a list `22,443` |
| `--firewall` | | Evaluate only firewalls whose name or ID contains this string |
| `--json` | | JSON output |

`diagnose`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--snapshot` | required | Path to a snapshot file |
| `--from`, `--to` | required | Address, CIDR, instance ID, or `Name` tag |
| `--proto` | `tcp` | `tcp`, `udp`, or `icmp` |
| `--port` | | Destination port, required for `tcp` and `udp` |
| `--symptom` | | `connection-refused`, `no-route-to-host`, `timeout`, `connect-then-stall`, `icmp-ok-tcp-fails` |
| `--skip-firewall` | | Evaluate routing and NACLs only |
| `--json`, `--markdown` | | Render as JSON or markdown instead of text |

`compare`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--snapshot` | required | Path to a snapshot file |
| `--from`, `--to` | required | Failing path source and destination |
| `--ref-from` | required | Reference path source, the one that works |
| `--ref-to` | `--to` | Reference path destination |
| `--proto` | `tcp` | `tcp`, `udp`, or `icmp` |
| `--port` | | Destination port, required for `tcp` and `udp` |
| `--symptom` | | Describes the failing path only |
| `--skip-firewall` | | Evaluate routing and NACLs only, on both paths |
| `--json`, `--markdown` | | Render as JSON or markdown instead of text |

`diff`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--from` | required | Path to the earlier snapshot |
| `--to` | required | Path to the later snapshot |
| `--json`, `--markdown` | | Render as JSON or markdown instead of text |

`test`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--snapshot` | required | Path to a snapshot file |
| `--flows` | required | Path to a declared flow file, YAML or JSON |
| `--skip-firewall` | | Evaluate routing and NACLs only, on every flow |
| `--json`, `--markdown` | | Render as JSON or markdown instead of text |

`verify`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--snapshot` | required | Path to a snapshot file |
| `--from`, `--to` | required | Source and destination IP address |
| `--proto` | `tcp` | `tcp` or `udp` |
| `--port` | | Destination port, required for `tcp` and `udp` |
| `--config` | | `aws-netpath.yaml`, used to look up the profile |
| `--profile` | | AWS profile for the analyzer call |
| `--region` | source subnet region | Region to run the analysis in |
| `--skip-aws` | | Evaluate the model only, skip the AWS comparison |
| `--timeout` | `2m` | AWS analysis timeout |
| `--json`, `--markdown` | | Render as JSON or markdown instead of text |

`mcp` takes no flags. Register the binary with an MCP client:

```json
{"command": "aws-netpath", "args": ["mcp"]}
```

`--json` and `--markdown` together is a usage error: two renderings of one report cannot both be the
output, and choosing one by precedence would hand a caller a shape it did not ask for. Text is the
default because an operator gets prose without asking and a machine asks.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Traffic permitted with every layer evaluated, or the command succeeded |
| 1 | Traffic blocked, a difference or change found, or the answer established only in part — usable output either way |
| 2 | Usage error, unknown address in the snapshot, or failure |

The line between `1` and `2` is whether there is output worth reading. A blocked flow, a difference
between two paths, a change between two collections, a collection that recorded errors: all of those
ran and produced a report. A missing flag, an unreadable snapshot, an endpoint matching two instances:
nothing to read.

The line between `0` and `1` is the one that matters more. An abstention is not a pass, so `0` is not
"nothing was shown to block this" — it is "nothing blocks this, and every layer was checked".

## Why

Cloud providers already ship reachability tools, and they are useful. They also share three limits
that matter once a network gets complicated:

**They answer one question at a time.** AWS Reachability Analyzer charges per analysis and takes tens
of seconds to tell you about a single 5-tuple. That price is fine for one question and prohibitive for
the ten thousand questions that would actually characterise your network.

**They are blind to parts of the policy.** AWS documents that Reachability Analyzer does not support
domain lists, raw Suricata rules, or rule options. If your firewall policy leads with a domain
allowlist, the analyzer walks past it and leaves you to guess.

**They stop at the region boundary.** Reachability Analyzer evaluates one region. Traffic crossing a
transit gateway peering is inspected by a firewall at *each* end, so no single run can tell you
whether the flow survives both. A green result in the source region proves nothing about the
destination region.

**And none of them can see the host.** AWS configuration can be entirely correct while `firewalld`
rejects the source or nothing is listening on the port. That gap is what the rest of this tool is for.

aws-netpath takes the opposite approach. Collect the configuration once into a local model, then
evaluate flows symbolically against that model. Queries become free and instant, which makes it worth
asking questions you would never pay to ask.

## How it works

**Flows are sets, not tuples.** A query carries a set of source prefixes, destination prefixes, a
protocol, and a set of destination ports. Each policy the traffic meets narrows that set. Whatever
reaches the far end is precisely the traffic that is permitted. Because the algebra supports
subtraction, a rule matching part of a query splits it rather than forcing a yes or no, which is what
makes the port split above fall out for free.

**The model is provider-neutral.** Collectors translate cloud resources into the types in
`internal/model`; the engine only ever sees those types. Address space that isn't in the cloud at all,
such as an on-premises range behind Direct Connect, is an ordinary node. A destination does not have
to live in AWS.

**Every verdict cites a rule.** Decisions carry the rule group, priority, and SID that produced them.
A verdict you cannot trace is a verdict you cannot act on.

**Uncertainty is reported, never guessed.** A layer that cannot be authoritatively evaluated reports
`ABSTAIN` with a reason instead of a pass, and any verdict resting on it is marked not authoritative. A
simulator that is confidently wrong is worse than one that admits what it cannot see. Every condition
that produces an abstention is listed in
[abstention and what it costs a verdict](#abstention-and-what-it-costs-a-verdict), along with the
limitations behind them.

**Read-only by construction.** No mutating operation is performed on AWS resources or host state.
Enforcement is an explicit allowlist, not a convention — see [the next section](#read-only-by-construction)
for every action and command it permits.

## Read-only by construction

Nothing here changes an AWS resource or host state. That is a property of the code rather than a
promise about it: `internal/guardrail` holds one allowlist of AWS API actions and one allowlist of host
executables. Every host command is checked against its allowlist before dispatch, with no exception;
the AWS action allowlist is checked at the call sites that consult it, which is not yet every call
site — the caveats below say where.

Matching is exact and refusal is the default. `describesubnets`, `ec2:DescribeSubnets`,
`DescribeSubnets ` with a trailing space, `DescribeSubnets*`, and `/usr/bin/ss` are all rejected,
because none of them is literally the allowlisted name. A rejection names what was rejected, and
carries one of three sentinel errors so a caller can tell a policy refusal from a transport failure:
`ErrActionNotAllowed`, `ErrCommandNotAllowed`, `ErrUnsafeArgument`.

This section is written from `internal/guardrail/guardrail.go`, which is the only place either
allowlist exists. `guardrail.AllowedActions()` and `guardrail.AllowedHostCommands()` return the same
two lists at runtime, sorted, so an operator can print what a given build permits rather than trusting
a document to have kept up.

### Allowlisted AWS API actions

Twenty-one actions, grouped by the command that needs them so the groups map onto an IAM policy. The
service column is the IAM prefix.

`collect` — fourteen actions, every one a read:

| Action | Service | What it is for |
| --- | --- | --- |
| `GetCallerIdentity` | `sts` | Confirm a profile authenticates, and discover the account ID a snapshot is stamped with; a config-declared account ID is checked against it |
| `DescribeVpcs` | `ec2` | VPCs and their CIDR blocks |
| `DescribeSubnets` | `ec2` | Subnets, their CIDR blocks, and their availability zones |
| `DescribeRouteTables` | `ec2` | Routes, their targets, and which route table each subnet is associated with |
| `DescribeSecurityGroups` | `ec2` | Ingress and egress rules |
| `DescribeNetworkAcls` | `ec2` | Subnet-level allow and deny rules |
| `DescribeNetworkInterfaces` | `ec2` | Attributes an address to a security group, an instance, and a subnet |
| `DescribeTransitGateways` | `ec2` | Transit gateways |
| `DescribeTransitGatewayAttachments` | `ec2` | What is attached to each transit gateway |
| `DescribeTransitGatewayRouteTables` | `ec2` | Transit gateway route tables |
| `SearchTransitGatewayRoutes` | `ec2` | The routes inside a transit gateway route table |
| `DescribeFirewall` | `network-firewall` | Firewall, its VPC, and its subnet mappings |
| `DescribeFirewallPolicy` | `network-firewall` | Default actions, rule order, and rule group references |
| `DescribeRuleGroup` | `network-firewall` | Rules, domain targets, and rule variables |

`diagnose` and `compare`, for the host layers, when a Systems Manager client is available:

| Action | Service | What it is for |
| --- | --- | --- |
| `DescribeInstanceInformation` | `ssm` | Whether the instance is managed at all; if not, the host layers abstain |
| `SendCommand` | `ssm` | Deliver one allowlisted host command |
| `GetCommandInvocation` | `ssm` | Read that command's output back |

`verify`, for the Reachability Analyzer cross-check:

| Action | Service | What it is for |
| --- | --- | --- |
| `CreateNetworkInsightsPath` | `ec2` | Describe the path to be analysed |
| `StartNetworkInsightsAnalysis` | `ec2` | Run one analysis of that path |
| `DescribeNetworkInsightsAnalyses` | `ec2` | Poll for the result |

`verify` builds its client the same way `collect` does, so it needs `sts:GetCallerIdentity` too.

One action is allowlisted and issued by no current code path:

| Action | Service | Status |
| --- | --- | --- |
| `DescribeInstances` | `ec2` | Permitted for instance lookup; nothing in the tree calls it today |

**The calls that are not reads.** `CreateNetworkInsightsPath` and `StartNetworkInsightsAnalysis` are
the only allowlisted actions that create anything, and `verify` deletes the path it created once the
run finishes. Every other allowlisted action reads: the `Describe*` calls, plus
`SearchTransitGatewayRoutes`, `GetCallerIdentity`, and `GetCommandInvocation`. The creating pair is
still
consistent with the guarantee: what they create is an analysis of your network, not a piece of it. No
route, security group, NACL, firewall policy, or rule group is touched, and nothing that carries
traffic is created or removed. They also only run under `verify`, they are billable per analysis, and
`--skip-aws` avoids them entirely. Every other command reads a snapshot from disk and issues no AWS
call at all.

Two caveats if you derive an IAM policy from these tables. Tagging the objects `verify` creates is part
of both create calls, so a policy needs `ec2:CreateTags` alongside them. And the allowlist is presently
narrower than the set of calls the code issues: `verify`'s path cleanup (`DeleteNetworkInsightsPath`)
and three read-only collector calls (`GetTransitGatewayRouteTableAssociations`,
`DescribeVpcPeeringConnections`, `ListFirewalls`) reach AWS without being on the list at all, and only
four of the listed actions are checked at their call site today — `DescribeNetworkInterfaces`,
`DescribeInstanceInformation`, `SendCommand`, and `GetCommandInvocation`. Reconciling that is a change
to `internal/guardrail` and its callers, not to this document, so the tables above stay as they are:
what the enforcer permits, nothing added.

### Allowlisted host commands

Four executables. Each is dispatched through Systems Manager, and each of the five checks that use them
is built from a fixed template in the source, where only the `{placeholder}` positions can vary:

| Command | What it is for | Templates in the source |
| --- | --- | --- |
| `ss` | Whether anything is listening on the destination port | `ss -tlnp` |
| `firewall-cmd` | Whether the host firewall admits the source | `firewall-cmd --zone={zone} --list-rich-rules`, `firewall-cmd --zone={zone} --list-services` |
| `ip` | Which interface the host would actually use to reach the destination | `ip route get {dst}` |
| `ping` | Whether a large packet survives the path, which is what explains a payload stall | `ping -M do -s {size} -c 2 {dst}` |

The executable allowlist on its own is not the whole story, and it is worth being precise about why.
`ip` and `firewall-cmd` both have mutating subcommands; `ip route add` and
`firewall-cmd --add-rich-rule` are real commands. What keeps them out of reach is that a probe never
assembles a command — it names a template and supplies values for its placeholders. Every other element
of the invocation is literal text decided in the source, so the subcommand is not something a caller
can choose.

### Why the host command allowlist is the real control

`SendCommand` is on the AWS action allowlist, and `SendCommand` can run anything a host can run.
Permitting it says nothing about what gets run. So the gate that carries the guarantee is not the API
allowlist but the host command allowlist, checked against the assembled argv before dispatch rather
than after.

That gate is first and it is fail-closed. An unlisted executable is refused without its arguments being
consulted, because nothing about the arguments can make an unlisted executable acceptable. In
particular `sh -c "ss -tlnp"` is refused: `argv[0]` is `sh`, and `sh` is not on the list. An empty argv
is refused too — there is nothing to check, so there is nothing to permit.

### Argument safety

**Commands are argument lists, never shell strings.** A command is a `[]string` where `argv[0]` is the
executable and each remaining element is exactly one argument. There is no code path that builds a
command by formatting text.

**Shell metacharacters are rejected in every argument, in every position.** Three families:

- chaining and redirection — `;` `&` `|` `<` `>` `$` `` ` `` `(` `)`
- quoting and escaping, which could reintroduce the first family — `\` `'` `"`
- expansion and globbing — `*` `?` `[` `]` `{` `}` `~` `!`

Control characters are rejected separately, which covers newline, carriage return, tab, NUL, and
delete. The screen is load-bearing rather than belt and braces: by the transport constraint below, the
argv is joined into one script line that a shell on the probed host does interpret.

**Validation runs twice, and before dispatch both times.** Each substituted value is screened on its
own first, so the error names the placeholder that was supplied rather than a position in an assembled
argv. The finished invocation is then screened as a whole, which also catches a template whose own
literal text is unsafe.

**One transport constraint.** Systems Manager carries a script line rather than an argv, so the argv is
joined with spaces at the last moment. Joining is only faithful while no element is empty and no
element contains whitespace, so `internal/host` requires exactly that and refuses anything else with
`ErrArgumentNotRepresentable`. The alternative — quoting the elements — would mean putting quote
characters back into arguments, which is what the metacharacter screen exists to prevent.

## Abstention and what it costs a verdict

A layer that cannot be authoritatively evaluated reports `ABSTAIN` with a reason. It is never folded
into a pass, never dropped from the report, and never left implicit. `ABSTAIN` is a first-class layer
verdict alongside `PASS` and `BLOCKED`, and the reason is mandatory — `internal/model` refuses to emit
an abstention without one, because an abstention that cannot explain itself is indistinguishable from a
silent pass.

Every condition that produces one is below, grouped by the layer it is reported under, so an abstention
you saw in output can be looked up by where it appeared. The reason strings are the ones the tool
emits; `<angle brackets>` mark the values filled in at runtime.

### What an abstention costs the verdict

**It is never aggregated as a pass.** Several findings for one layer are combined by taking the
strongest verdict — `BLOCKED` over `ABSTAIN` over `PASS` — so a layer that abstained anywhere never
reports as cleared, and the reason from every contributing finding is kept.

**It gets its own report section.** `query` and `diagnose` print `abstentions` after the blocking layer
and the cleared layers; `firewall` prints the rule groups it could not evaluate under the same heading.
The section is present even when empty, where it reads `no layer abstained` — an absent section reads
as a report with nothing to say about what went unevaluated.

**The report says whether it could have changed the answer.** With no blocker found, every abstention
qualifies: an unevaluated layer might have been the one blocking. With a blocker found, only
abstentions earlier in flow order qualify, because a layer after the block cannot un-drop traffic
another layer was shown to drop. So the section closes with either
`<layers> could have changed this verdict` or `no abstention could have changed this verdict`. Flow
order is `resolution`, `route`, `nacl`, `security_group`, `firewall`, `return_path`, `host_firewall`,
`host_listener`.

**A verdict resting on one is banner-marked.** Text output prefixes the line with `!!`, markdown emits
`> **Not authoritative.**`, and JSON carries `"authoritative": false`. The banner names the layers and
quotes their reasons rather than saying that an abstention occurred, because the operator's next move
is to go and evaluate whichever layer could not be read.

**It changes the exit code.** `exit 0` means the traffic is permitted *and* every layer was checked. An
answer resting on an abstention is exit `1`: usable, and short of the question that was asked. See
[exit codes](#exit-codes).

The other commands carry the same fact under their own names. `compare` reports a layer that abstained
on either path under `incomplete comparisons` rather than as a match, and states that the comparison is
not authoritative. `test` reports a declared flow whose reachability was not established as
`inconclusive` — neither a pass nor a failure. `collect` records what it could not read in
`collection_errors`, because a resource missing from a snapshot is what a later abstention will be
about.

### resolution

| Trigger | Reason emitted | What to do |
| --- | --- | --- |
| The source address is in no collected subnet | `source <addr> is not in any collected subnet (re-collect with the owning account, or ping proves live connectivity)` | Re-collect with the account that owns the address. The overall verdict is `UNKNOWN` and the report adds `verdict UNKNOWN does not mean the network blocks this flow` |

A *destination* outside the snapshot is not a resolution abstention: address space belonging to no
collected VPC is an ordinary external node, so resolution passes and the abstentions land on
`security_group` and `return_path` instead. Declaring the range under `external` in the config makes it
a named node rather than an anonymous one; it does not make its policy evaluable.

### route and nacl

Neither layer has an abstention condition. Routing decisions are made from route tables that are
either in the snapshot or not, and a NACL in the snapshot is evaluated in full. What that means where
the resource is *missing* is covered under [known limitations](#known-limitations) — it is the one
place the abstention stance is not yet carried through the code.

### security_group

| Trigger | Reason emitted | What to do |
| --- | --- | --- |
| The endpoint address has no collected network interface, so nothing attributes a group to it | `<role> <addr> has no collected network interface, so its security groups were not evaluated; re-collect with the account owning that address` | Re-collect with the account that owns the address |
| The interface is collected but carries no groups | `<role> interface <eni> has no collected security groups` | Check the interface really has no groups; if it does, the collection was partial |
| The interface names groups the snapshot does not contain | `<role> interface <eni> references security groups absent from the snapshot: <ids>` | Re-collect with the account owning those groups |
| No rule matched, but a rule could not be decided — a managed prefix list that is not expanded, or a referenced peer group that was not collected | `no <direction> rule on <role> interface <eni> matched <flow>, but the groups could not be fully evaluated (<constructs>)`, where a construct is `managed prefix list <id> is not expanded in the snapshot`, `referenced group <id> is not in the snapshot`, or `groups absent from the snapshot: <ids>` | Re-collect the missing group; a prefix list has to be checked by hand, since the snapshot holds the reference and not its entries |
| The destination is outside the snapshot, so there is no destination-side policy to evaluate | `destination <addr> lies outside the snapshot, so its security groups were not evaluated` | Nothing, if the destination genuinely is not in AWS. Otherwise re-collect with the owning account |

The fourth row is the one worth understanding: an undecidable rule is neither a match nor a miss, so
"nothing matched" cannot be reported as a block. The unexpanded prefix list might have been the entry
that permitted the traffic.

### firewall

Every firewall abstention is rendered as `<firewall>: <rule group> (priority <n>): <reason>`, so a flow
inspected at two points says which one could not be evaluated.

| Trigger | Reason emitted | What to do |
| --- | --- | --- |
| The policy evaluates stateful rules by action precedence rather than written order | `policy uses DEFAULT_ACTION_ORDER, whose precedence aws-netpath does not model` | Read the policy by hand, or move it to `STRICT_ORDER` if the estate permits |
| The policy references a rule group the snapshot does not contain | `rule group is referenced by the policy but absent from the snapshot` | Re-collect with the account owning the rule group |
| A rule group matches on TLS SNI or HTTP Host | `contains a domain list, which matches on TLS SNI or HTTP Host rather than the 5-tuple` | Read the domain list by hand: nothing in a 5-tuple can decide it |
| A rule group is authored as raw Suricata rules whose IP set variables cannot be resolved | `contains raw Suricata rules without resolvable IP set variables` | Supply the rule variables in the group, or read the rules by hand |
| A rule group itself declares action-order evaluation | `uses DEFAULT_ACTION_ORDER, whose precedence aws-netpath does not model` | As for the policy-level case above |
| A `rules_string` group could not be expanded into 5-tuple rules | `Suricata rules could not be expanded: <problems>`, where a problem is `unsupported rule "<line>"` (a rule outside the 5-tuple grammar, including rule options other than `sid`) or `undefined IP set variable "$<name>"`; a group where only some rules failed reports `partial expansion: <problems>` | Read the quoted lines by hand. They are quoted precisely so you do not have to find them |
| One rule's header could not be compiled | `rule <n> could not be parsed: <detail>`, where the detail names the part that failed — `source`, `destination`, protocol, `source port`, or `destination port` | Check the named field in that rule; the rest of the group was still evaluated |
| No rule and no default action decided any of the traffic | `evaluation recorded no decision for the traffic` | Usually an empty policy or a flow the policy says nothing about; check the policy's default actions |

Any one of these makes the whole firewall verdict abstain, not just the group it came from: an
unevaluated rule group might have passed traffic this evaluation dropped, or dropped traffic it passed.
The `firewall` command says so directly — `an unevaluated rule group might have been the one that
decided this flow`, against `every rule group in the path was evaluated` when there is nothing to
report.

### return_path

The reverse direction is walked as a flow in its own right, because routing in AWS is per-direction.

| Trigger | Reason emitted | What to do |
| --- | --- | --- |
| The reverse walk crosses an inspection point | `return routing reaches <src>, but firewall policy was not evaluated in the reverse direction at <firewalls>: stateful inspection permits the response to an already permitted flow, and the client ephemeral port is unknown, so a reverse-direction firewall verdict would not be authoritative` | Nothing, usually. This is a deliberate refusal: evaluating the reverse flow against the policy would manufacture a drop that does not happen |
| The destination is in a declared external network, whose routing is not collected | `destination <addr> belongs to declared external network <name>, whose routing is not in the snapshot, so the return direction could not be walked` | Check the return route on the far side by hand |
| The destination is in no collected subnet at all | `destination <addr> is not in any collected subnet, so the return direction has no route table to walk; re-collect with the account owning that address` | Re-collect with the account that owns the address |

A return direction that is *blocked* is not an abstention. It is reported as a note —
`return direction is blocked at <hop>; the forward verdict does not account for the response path` —
and promoting it to the primary blocker is the correlator's decision. An asymmetric path, where the
two directions resolve to different next hops, is an observation rather than a verdict.

### host_firewall and host_listener

Both host layers carry the prefix `host layer unverified: ` in front of the reason, and the sentinel
behind it names the category: `instance is not an ssm-managed linux host`,
`host command could not be delivered`, `host command did not complete in time`, or
`host command argument not representable`. The conditions below abstain **both** host layers at once,
because none of the probes could run.

| Trigger | Reason emitted | What to do |
| --- | --- | --- |
| No Systems Manager client was supplied — the current state of the CLI and the MCP server | `host command could not be delivered: the diagnose operation was given no systems manager client, so the host was not probed` | Nothing yet; see [known limitations](#known-limitations) |
| The destination resolves to an address the snapshot attributes to no instance | `instance is not an ssm-managed linux host: destination <input> resolved to <description>, which the snapshot attributes to no instance` | Pass the instance explicitly, or re-collect so the interface is attributed |
| Systems Manager does not know the instance, or reports it as something other than a managed Linux host | `instance is not an ssm-managed linux host: <id> is not registered with ssm`, `… ssm does not recognise <id>: <err>`, `… <id> agent ping status is <status>`, `… <id> platform is <platform>`, `… <id> is not an instance id` | Install or repair the SSM agent, or accept that this host's layers cannot be read |
| The command could not be dispatched or its result could not be fetched | `host command could not be delivered: ssm could not be asked whether <id> is managed: <err>`, `… <cmd> on <id>: <err>`, `… <cmd> on <id>: ssm accepted the command without returning a command id`, `… <cmd>: ssm reported <status>` | Check the SSM permissions and the agent; the reason quotes the command that was refused |
| The command did not finish in time | `host command did not complete in time: <cmd> on <id> after <timeout>`, or `… <cmd>: ssm reported <status>` | Retry; a timeout leaves that check unverified and the others still answer |
| An argument could not be carried faithfully over Systems Manager | `host command argument not representable: empty argument`, `host command argument not representable: "<value>" contains whitespace` | A bug or an unusual endpoint value; the refusal is deliberate rather than a fallback to quoting |

These abstain `host_firewall` alone:

| Trigger | Reason emitted | What to do |
| --- | --- | --- |
| The check was asked something it cannot match on | `host firewall check: no source address to match against the allowlist`, `host firewall check: no destination port`, `host firewall check: protocol <proto> carries no ports, so no port allowance can be matched` | Supply a port, or accept that a portless protocol has no port allowance to match |
| `firewall-cmd` exited non-zero — firewalld not running, the binary absent, or the probe unauthorised | `<command line> exited <code>: <detail>` | None of those means the port is open. Check firewalld on the host |
| The zone output could not be parsed | `could not read the output of <command>: <err>` | Read the zone by hand; the output shape was not one this parser recognises |
| A rich rule governs the traffic but cannot be evaluated | `<command line>: rule cannot be evaluated (<construct>): <raw rule>`, where the construct is `<key> element is not modelled`, `unrecognised token "<key>"`, or `source <key>=<value> cannot be resolved to addresses` | Read the quoted rule. It might be the rule that decides, so nothing later may be trusted to decide instead |
| The zone allows a named service whose ports this tool does not know | `zone <zone> allows service <names>, whose ports are not known to aws-netpath, so <proto>/<port> cannot be ruled out` | Check what that service opens; a name this tool does not recognise cannot be used to declare the zone closed |

And these abstain `host_listener` alone:

| Trigger | Reason emitted | What to do |
| --- | --- | --- |
| The check was asked something `ss -tlnp` cannot answer | `listener check: no destination address to check a listener against`, `listener check: no destination port`, `listener check: listener reports tcp listeners only, and the destination protocol is <proto>` | For UDP there is no listening state to report, so this layer stays unverified by design |
| `ss` exited non-zero, so no sockets were enumerated | `<command line> exited <code>: <detail>` | Check the host; there is no output to read and so no conclusion to draw |
| The socket table could not be parsed | `could not read the output of <command>: <err>` | Read `ss -tlnp` by hand |

Nothing listening is a **block**, not an abstention: `no process listening on <proto>/<port> at <addr>`,
citing what was listening instead. A socket on the right port bound to the wrong address is called out
separately, because the operator's next step differs.

The two supporting host checks — `ip route get` and the large-packet `ping` — are observations rather
than layers, and they abstain on the same transport failures. The `ping` probe also abstains on
`no reply to a <n>-byte payload to <addr> and no fragmentation-needed message, which is equally
consistent with icmp being filtered`, which is the honest reading of silence.

### Known limitations

Documented rather than hidden, which is the same stance as the abstentions above.

**Modelling.**

- A destination outside the snapshot is evaluated on routing alone. Destination-side security groups
  and the return direction abstain, and nothing on the far side is checked.
- The gateway-subnet-to-firewall-endpoint hop inside an inspection VPC is not modelled separately.
  Firewall evaluation happens at VPC entry, so a route table on the firewall subnet that misdirects
  traffic is not caught.
- Domain allowlists, raw Suricata rules, rule options outside the `sid` the 5-tuple grammar reads, and
  `DEFAULT_ACTION_ORDER` policies are not evaluated. They abstain, per the firewall table above.
- Transit gateway policy tables and Connect attachments are not modelled.
- IPv4 only. IPv6 address space is not evaluated.
- Return-direction firewall policy is deliberately not evaluated, since the client ephemeral port is
  not knowable from configuration.

**Host.**

- Only Linux hosts running the Systems Manager agent can be probed, and only `firewalld` is understood
  as a host firewall. A Windows host, an unmanaged host, or a host using `nftables` or `iptables`
  directly leaves both host layers abstaining.
- No packet capture and no live traffic inspection. Every verdict comes from configuration and
  read-only host queries; the one probe that puts traffic on the wire is the large-packet `ping`, and
  it runs only when a symptom implicates path MTU.
- No remediation. Nothing here changes an AWS resource or host state — see
  [read-only by construction](#read-only-by-construction).

**Current build state.**

- Host probing abstains in practice. Neither the CLI nor the MCP server opens a Systems Manager
  client, so every `diagnose` and `compare` run reports both host layers as unverified with the "no
  systems manager client" reason above. The host evaluators themselves are built and tested; what is
  missing is the client that reaches a host.
- The AWS action allowlist is not consulted at every call site, and is narrower than the set of calls
  the code issues. The detail is in
  [read-only by construction](#read-only-by-construction) and is not repeated here.

**Where the abstention stance is not yet carried through the code.** Four cases report something other
than an abstention today, and each is a gap rather than a decision:

- A NACL absent from the snapshot produces no `nacl` layer at all — neither a pass nor an abstention.
  The layer is simply missing from the report.
- A route target missing from the snapshot is reported as a routing **block**, with the reason naming
  what to do:
  `TGW route targets <id> which is not in the snapshot (add the owning account to aws-netpath.yaml and re-collect)`.
  That reads as the network having dropped the traffic when the truth is that the tool cannot see the
  next hop. The same applies to `peer TGW <id> not in snapshot` and `no route table on peer TGW`.
- An attachment or next-hop kind the walk does not model — a Connect attachment among them — is
  likewise reported as a block: `unsupported attachment kind <kind>` and `unsupported next hop <kind>`.
- `--skip-firewall` suppresses forward-direction firewall evaluation and records no abstention for it,
  so a permitted verdict under `--skip-firewall` is a narrower claim than a permitted verdict from a
  full run. The reverse direction still abstains, and says which inspection points it skipped.

## Layout

| Package | Role |
| --- | --- |
| `internal/flow` | Symbolic flow algebra: sets of prefixes and ports, with subtraction |
| `internal/nfw` | Network Firewall and Suricata evaluation, with abstentions |
| `internal/model` | Provider-neutral network model, snapshot schema, and verdict types |
| `internal/collect`, `internal/collect/aws` | Multi-profile AWS ingestion |
| `internal/awsx` | AWS SDK clients built from shared config profiles |
| `internal/snapshot` | Snapshot read/write and schema version enforcement |
| `internal/query` | Route walk, NACLs, security groups, inspection points, return path |
| `internal/host` | Read-only host probes over Systems Manager |
| `internal/symptom` | Observed client error to candidate layers, pure logic |
| `internal/correlate` | Layer findings into one verdict, with precedence |
| `internal/compare` | Failing path against a reference path that works |
| `internal/diffsnap` | What changed between two snapshots |
| `internal/flowtest` | Declared flows judged against the engine |
| `internal/verify` | Cross-check against AWS Reachability Analyzer |
| `internal/format` | Text, markdown, and JSON renderings of one report |
| `internal/guardrail` | Read-only API and host command allowlists |
| `internal/config` | Multi-account configuration |
| `internal/ops` | The operations the CLI and the MCP server both call |
| `internal/cli` | Command line surface: flags, rendering, exit codes |
| `internal/mcpserver` | The same operations over MCP on stdio |

`internal/flow`, `internal/nfw`, `internal/model`, `internal/symptom`, and `internal/correlate` carry
no cloud SDK dependency, so evaluation stays testable with no account and no network access.

## Prior art

None of the ideas here are new. Configuration-based verification, symbolic path analysis, and
read-only host inspection all predate this tool, and in several cases the prior art does its own job
better than aws-netpath does. What follows is what each one is for, and where this tool sits relative
to it.

**[Batfish](https://github.com/batfish/batfish)** pioneered configuration-based network verification
and remains the reference implementation of the idea. It parses vendor configuration from Cisco,
Juniper, Arista, and many more, builds a dataplane from it, and answers reachability questions
symbolically. For a physical or multi-vendor network it is the better tool, and aws-netpath does not
attempt that ground at all: there is no config parser here and no non-AWS device model.

aws-netpath differs in three ways that matter for a cloud estate. It reads live AWS APIs across
multiple accounts rather than config text, so there is no config export step and no drift between the
file and the account. It models AWS Network Firewall, including Suricata rule evaluation, as a first
class layer rather than as an opaque appliance. And it ships as one dependency-free binary — no JVM, no
service to run, no container — which is what makes it usable from a jump host or a CI job.

**[AWS Reachability Analyzer](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html)**
is the provider's own answer, computed by AWS from the state AWS actually holds. That makes it ground
truth in a way a third-party model cannot be, which is precisely why `verify` cross-checks this tool's
verdicts against it instead of competing with it: when the two disagree, the bug is presumed to be
here. The reasons it is not the engine — per-query cost, single-region scope, and the policy features
it does not model — are set out in [why](#why) and not repeated here.

**[AWS VPC Network Access Analyzer](https://docs.aws.amazon.com/vpc/latest/network-access-analyzer/what-is-network-access-analyzer.html)**
answers a different question, and answers it well. You give it a Network Access Scope describing access
you consider unintended, and it reports every path in your network that matches — an open-ended search
across the estate, aimed at posture and compliance. aws-netpath asks the narrow question instead: this
source, this destination, this protocol, these ports, permitted or not, and if not, which rule stopped
it. Use Network Access Analyzer to find out what is possible; use this to find out why one specific
thing is failing right now.

**[VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html) and
[traffic mirroring](https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html)**
observe what happened. No configuration model can do that — flow logs see real packets, real rejects,
and real volume, including traffic from sources nobody thought to ask about. They are also the only way
to confirm that a path you believe is open is one anything is actually using. Their limit is the
inverse: they cannot tell you about traffic that has not been sent, they cannot explain *which* rule
produced a `REJECT`, and reading them requires the failure to have already occurred. aws-netpath
evaluates configuration, so it answers before the attempt and names the rule; it does not and cannot
replace observation. The two pair naturally — a flow log `REJECT` tells you where to point `diagnose`.

**Host-side tooling operators already use by hand.** `ss -tlnp`, `firewall-cmd --list-rich-rules`,
`ip route get`, and `ping` with a fixed payload size for path MTU are the commands an experienced
engineer runs over SSH when the cloud config looks fine. They are authoritative and they are not going
away. aws-netpath does not replace them; it runs those same read-only commands over Systems Manager,
parses the output, and correlates the result with the cloud verdict so that "the security group allows
it but nothing is listening" is a single answer rather than two sessions and a mental join. Every
command it may run is allowlisted and listed in
[read-only by construction](#read-only-by-construction). Note the current state honestly: neither the
CLI nor the MCP server opens a Systems Manager client yet, so the host layers abstain rather than
probe — see [known limitations](#known-limitations).

**The internal predecessor this repository absorbed** is where most of the engine came from, and it
deserves saying plainly rather than being quietly folded in. That project — never publicly released, so
there is nothing to link to — is the origin of the symbolic flow algebra in `internal/flow`, the Network
Firewall and Suricata evaluator in `internal/nfw`, multi-profile collection, the snapshot model, the
offline route/NACL/security-group walk, and the Reachability Analyzer cross-check. Those are inherited
rather than written here, and the abstention stance came from there too. What this repository added is
the host layer, symptom classification, verdict correlation across cloud and host, baseline comparison,
return-path asymmetry, snapshot diffing, declared flow tests, the guardrail allowlists, and the MCP
server.

Taken together, the position is narrow on purpose: collect once, then evaluate any number of flows
offline; order the investigation by the symptom the operator actually saw; abstain out loud rather than
guess; correlate the cloud layers with the host layers in one verdict; cite the rule behind every
decision; and expose the same operations to a CLI and to an agent over MCP from one binary.

## Development

```bash
go build ./...
go test ./...                                  # all unit + regression tests
go test ./internal/query/ -run Regression -v   # reachability regression only
go test ./internal/verify/ -v                  # model vs AWS comparison logic
go vet ./...
gofmt -l .
```

### Release build

```bash
./scripts/release.sh                              # every platform, into dist/
VERSION=v0.3.0 ./scripts/release.sh               # version pinned by hand
PLATFORMS="linux/arm64" ./scripts/release.sh      # one target only
```

One statically linked binary per platform — `linux/amd64`, `linux/arm64`, `darwin/amd64`,
`darwin/arm64`, `windows/amd64` — plus a `SHA256SUMS` covering them, all under the gitignored `dist/`.
Every target builds with `CGO_ENABLED=0`, so nothing binds to the platform's libc and the binary can be
copied onto a host that has nothing else on it.

Builds are reproducible: `-trimpath` and `-buildvcs=false` keep the build machine out of the output, so
the same commit built anywhere on the same Go version produces the same bytes, and the published
checksum is worth checking.

```bash
sha256sum -c SHA256SUMS      # in dist/, or next to a downloaded release
```

The version comes from `git describe` — the tag when the commit carries one, `dev` when it does not —
and is stamped with the short commit into `internal/cli.Version`. `aws-netpath version` prints it back:

```plaintext
v0.3.0+a1b2c3d
```

An unstamped `go build` reports `dev`, so a local build never presents itself as a release. A build off
a tree with uncommitted changes is marked `-dirty`, because it cannot be reproduced from the commit.

The script is the local path. Pushing a `v*` tag builds and publishes the same five targets in CI
through the shared `actionsforge/actions` `go-binary-release.yml` reusable workflow, with the same
`CGO_ENABLED=0`, `-trimpath -buildvcs=false` and `SHA256SUMS`, stamping the tag into
`internal/cli.Version`.

## License

MIT. See [LICENSE](LICENSE).
