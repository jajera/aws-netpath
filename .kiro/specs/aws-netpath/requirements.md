# Requirements Document

## Introduction

`aws-netpath` models a network once, then answers reachability and diagnosis questions offline —
instantly, free, with a citation for every verdict.

It absorbs the `netprobe` engine (symbolic flow algebra, Network Firewall evaluation, multi-profile
AWS collection, snapshot model, offline query, and Reachability Analyzer cross-check) and extends it
with the parts no cloud API can see:

1. **Host-layer state.** AWS configuration can be entirely correct while `firewalld` rejects the
   source or nothing is listening on the port. In the incident that motivated this work, every AWS
   layer was clean and the cause was a host firewall allowlist built from a stale template.
2. **Symptom interpretation.** The client-side error is the strongest available clue.
   `Connection refused`, a timeout, and `No route to host` implicate different halves of the stack.
3. **Baseline comparison.** A failing path beside a working sibling path localises a fault faster than
   analysing the failing path alone.
4. **Agent surface.** The same capabilities over MCP, so an agent can run the method rather than a
   human recalling it.

Design stance inherited from `netprobe` and treated as non-negotiable: **uncertainty is reported,
never guessed.** A simulator that is confidently wrong is worse than one that admits what it cannot
see.

## Glossary

- **NetPath_System**: The `aws-netpath` application: CLI, MCP server, engine, collectors, probes.
- **Collector**: The module ingesting live AWS configuration into a Snapshot.
- **Snapshot**: A collected, provider-neutral model of network configuration, queryable offline.
- **Flow**: A set of source prefixes, a set of destination prefixes, a protocol, and a set of
  destination ports. Flows are sets, not single tuples.
- **Flow_Engine**: The module performing symbolic set operations on Flows, including subtraction.
- **Firewall_Evaluator**: The module evaluating Network Firewall policy against a Flow.
- **Path_Walker**: The module walking routes, NACLs, security groups, and transit gateways.
- **Host_Prober**: The module running read-only host checks over AWS Systems Manager.
- **Symptom_Classifier**: The pure-logic module mapping an observed client error to candidate Layers.
- **Return_Path_Checker**: The module evaluating the destination-to-source direction independently.
- **Comparator**: The module diffing a failing path against a reference path.
- **Correlator**: The module reconciling all Layer findings into one verdict.
- **Verifier**: The module cross-checking engine verdicts against AWS Reachability Analyzer.
- **Formatter**: The module rendering verdicts as text, markdown, or JSON.
- **Guardrail_Enforcer**: The module enforcing read-only API and host command allowlists.
- **Config_Loader**: The module loading and validating multi-account configuration.
- **Layer**: One evaluation stage. One of `RESOLUTION`, `ROUTE`, `NACL`, `SECURITY_GROUP`, `FIREWALL`,
  `RETURN_PATH`, `HOST_FIREWALL`, `HOST_LISTENER`.
- **Layer_Verdict**: The outcome for a Layer. Exactly one of `PASS`, `BLOCKED`, or `ABSTAIN`.
- **Abstention**: A `Layer_Verdict` of `ABSTAIN`, meaning the Layer could not be authoritatively
  evaluated. Never rendered as, or aggregated into, a pass.
- **Citation**: The evidence for a finding: resource ID, rule group, priority, SID, or command output.
- **Endpoint**: A source or destination as an IPv4 address, CIDR, instance ID, or `Name` tag.

## Cross-cutting semantics

Stated once, applying to every requirement.

1. **Abstention is not a pass.** Any Layer that cannot be authoritatively evaluated SHALL be reported
   as `ABSTAIN` with a reason. The Correlator SHALL NOT aggregate an Abstention as `PASS`, and the
   Formatter SHALL list Abstentions separately from cleared Layers.
2. **Every verdict carries a Citation.** A finding without a resource identifier, rule reference, or
   command output SHALL NOT be emitted.
3. **Read-only by construction.** The NetPath_System SHALL perform no mutating operation on AWS
   resources or host state. Enforcement is an allowlist in the Guardrail_Enforcer, not a convention.
4. **Multi-profile, no delegated administrator.** Each account SHALL be reached through its own
   credential profile. The NetPath_System SHALL NOT require AWS Organizations trusted access, a
   delegated administrator account, or an org-wide role.
5. **Offline evaluation.** Once a Snapshot exists, query, firewall, diagnose, and compare operations
   SHALL require no AWS API call and SHALL incur no per-query cost.
6. **Verdict precedence.** When multiple Layers report `BLOCKED`, the NetPath_System SHALL report the
   earliest Layer in flow order as primary and list the remainder as additional blockers.
7. **Exit codes.** `0` = permitted or command succeeded. `1` = blocked, or collection incomplete but
   usable. `2` = usage error or failure.
8. **Environment neutrality.** The NetPath_System SHALL contain no reference to any specific
   organisation, account identifier, profile name, hostname, or routable address range. Documentation,
   examples, fixtures, and tests SHALL use reserved documentation values only: `192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737), RFC 1918 ranges, and placeholder account IDs of the
   form `111122223333`. No behaviour SHALL depend on a particular region, account, or naming scheme.

## Requirements

### Requirement 1: Configuration Loading and Validation

**User Story:** As an operator, I want per-account profiles declared once, so I do not pass credentials
or regions on every invocation.

#### Acceptance Criteria

1. WHEN a config file is present, THE Config_Loader SHALL parse a list of accounts, each with an
   account ID, a credential profile name, and a list of regions.
2. WHEN a region value does not match the pattern `[a-z]{2,4}-[a-z]+-\d{1,2}`, THE Config_Loader SHALL
   return an error naming the field and the failed constraint.
3. WHEN no config file is supplied, THE Config_Loader SHALL accept a single profile and region list
   from command-line flags.
4. IF the config contains an unrecognised field, THEN THE Config_Loader SHALL return an error naming
   that field.
5. THE Config_Loader SHALL NOT require any cross-account role or organisation-level trust.

### Requirement 2: AWS Collection

**User Story:** As an operator, I want configuration collected once into a local model, so questions
afterwards are free and instant.

#### Acceptance Criteria

1. THE Collector SHALL ingest VPCs, subnets, route tables, security groups, NACLs, transit gateways,
   transit gateway route tables, and Network Firewall policy.
2. THE Collector SHALL ingest elastic network interfaces, so security groups can be attributed to
   endpoints.
3. THE Collector SHALL collect from every configured account and region in parallel.
4. WHEN collection of a resource type or scope fails, THE Collector SHALL record the failure in
   `collection_errors` in the Snapshot and SHALL continue collecting the remainder.
5. WHEN collection completes with recorded errors, THE NetPath_System SHALL exit `1` to signal
   incomplete but usable output.
6. THE Collector SHALL write a Snapshot containing a schema version and a collection timestamp.
7. WHEN a Snapshot is loaded whose schema version is unsupported, THE NetPath_System SHALL return an
   error stating the expected and found versions.

### Requirement 3: Symbolic Flow Evaluation

**User Story:** As an operator, I want to ask about ranges and port sets at once, and see the answer
split along the boundaries the rules actually draw.

#### Acceptance Criteria

1. THE Flow_Engine SHALL represent a Flow as sets of source prefixes, destination prefixes, and
   destination ports with a protocol.
2. THE Flow_Engine SHALL support intersection, subtraction, and emptiness testing on Flows.
3. WHEN a policy rule matches part of a Flow, THE Flow_Engine SHALL split the Flow rather than
   returning a single verdict for the whole.
4. THE Flow_Engine SHALL report, for a completed evaluation, precisely the subset of the original Flow
   that is permitted.
5. THE Flow_Engine SHALL operate with no dependency on any cloud SDK.

### Requirement 4: Path Evaluation

**User Story:** As an operator, I want a reachability verdict that names every policy the traffic met.

#### Acceptance Criteria

1. THE Path_Walker SHALL evaluate subnet route tables, transit gateway routes, and peering
   connections to determine the path a Flow takes.
2. THE Path_Walker SHALL evaluate NACLs in both the outbound and return directions.
3. THE Path_Walker SHALL evaluate security groups for source and destination endpoints when the
   Snapshot contains the relevant network interfaces.
4. WHERE a path crosses a region boundary, THE Path_Walker SHALL evaluate the policy at every
   inspection point rather than terminating at the first region boundary.
5. WHEN no route exists for a destination, THE Path_Walker SHALL report Layer `ROUTE` as `BLOCKED`
   citing the route table consulted.
6. WHEN a destination lies outside the Snapshot, THE Path_Walker SHALL evaluate routing only and SHALL
   record an Abstention for destination-side policy.

### Requirement 5: Firewall Evaluation

**User Story:** As an operator, I want the exact firewall rule that decided my traffic's fate.

#### Acceptance Criteria

1. THE Firewall_Evaluator SHALL evaluate stateful and stateless 5-tuple rules against a Flow.
2. WHEN a rule decides a Flow, THE Firewall_Evaluator SHALL cite the rule group, priority, and SID.
3. WHEN no rule matches, THE Firewall_Evaluator SHALL cite the policy default action.
4. WHEN evaluation meets a domain allowlist, a raw Suricata rule, a rule option it does not model, or a
   `DEFAULT_ACTION_ORDER` policy, THE Firewall_Evaluator SHALL record an Abstention naming the
   construct and SHALL declare the result non-authoritative.
5. WHEN a rule group referenced by a policy is absent from the Snapshot, THE Firewall_Evaluator SHALL
   record an Abstention rather than assuming an outcome.
6. WHERE traffic crosses two inspection points, THE Firewall_Evaluator SHALL report a verdict for each.

### Requirement 6: Endpoint Resolution

**User Story:** As an operator, I want to name endpoints the way I already think about them.

#### Acceptance Criteria

1. WHEN given a private IPv4 address, THE NetPath_System SHALL locate the owning network interface,
   instance, subnet, VPC, account, and region from the Snapshot.
2. WHEN given an instance ID or `Name` tag value, THE NetPath_System SHALL resolve it to a primary
   network interface and private IPv4 address.
3. IF an input matches more than one resource, THEN THE NetPath_System SHALL list every candidate with
   account and region and SHALL halt without selecting one.
4. IF an input matches no resource, THEN THE NetPath_System SHALL report the accounts and regions
   present in the Snapshot.
5. WHEN given a CIDR belonging to no collected VPC, THE NetPath_System SHALL treat it as an ordinary
   external node rather than an error.

### Requirement 7: Return Path Evaluation

**User Story:** As an operator, I want asymmetric routing found for me, because it presents as a
confusing partial failure rather than a clean block.

#### Acceptance Criteria

1. THE Return_Path_Checker SHALL evaluate the destination-to-source direction as a distinct Flow.
2. WHEN forward and return directions resolve to different transit gateways, attachments, or next
   hops, THE Return_Path_Checker SHALL report the path as asymmetric, citing both next hops.
3. WHEN a path is asymmetric AND traverses a stateful component, THE Correlator SHALL report this as
   the probable cause of a connect-then-stall Symptom.
4. WHEN the return direction is blocked while the forward direction is permitted, THE Correlator SHALL
   report the return direction as the primary blocker.

### Requirement 8: Host Layer Probing

**User Story:** As an operator, I want the host firewall and listener checked, because correct AWS
configuration does not mean the service is reachable.

#### Acceptance Criteria

1. WHERE the destination is a managed instance, THE Host_Prober SHALL determine whether a process is
   listening on the destination port.
2. WHERE the destination runs `firewalld`, THE Host_Prober SHALL determine whether the source address
   is permitted for the destination port or its named service.
3. THE Host_Prober SHALL match a source against allowlist entries by network containment, not string
   equality.
4. WHEN the source is absent from the host firewall allowlist, THE Host_Prober SHALL report Layer
   `HOST_FIREWALL` as `BLOCKED`, citing the allowlist entries found.
5. WHEN no process listens on the destination port, THE Host_Prober SHALL report Layer
   `HOST_LISTENER` as `BLOCKED`, citing the listener output.
6. IF the destination is not a managed instance, or a command cannot be delivered, THEN THE
   Host_Prober SHALL report the host Layers as `ABSTAIN` with the reason.
7. THE Host_Prober SHALL execute only commands in the Guardrail_Enforcer allowlist and SHALL NOT
   modify host configuration, service state, or files.

### Requirement 9: Symptom Classification

**User Story:** As an operator, I want the error I observed translated into a direction to investigate.

#### Acceptance Criteria

1. WHEN a Symptom is supplied, THE Symptom_Classifier SHALL map it to candidate Layers using this
   table:

   | Symptom | Mechanism | Candidate Layers |
   | --- | --- | --- |
   | `connection-refused` | RST returned | `HOST_LISTENER`, `HOST_FIREWALL` |
   | `no-route-to-host` | ICMP administratively prohibited | `HOST_FIREWALL`, `FIREWALL` |
   | `timeout` | packet silently discarded | `SECURITY_GROUP`, `NACL`, `ROUTE` |
   | `connect-then-stall` | state or MTU failure | `RETURN_PATH`, path MTU |
   | `icmp-ok-tcp-fails` | port-specific filter | `SECURITY_GROUP`, `HOST_FIREWALL` |

2. THE Symptom_Classifier SHALL distinguish silent discard from active rejection, and SHALL order host
   Layers before cloud Layers for actively rejected Symptoms.
3. THE Symptom_Classifier SHALL be a pure function requiring no API call and no Snapshot.
4. WHEN Layer findings contradict the supplied Symptom, THE Correlator SHALL report the contradiction
   rather than discarding either observation.
5. WHEN no Symptom is supplied, THE NetPath_System SHALL evaluate Layers in flow order.

### Requirement 10: Baseline Comparison

**User Story:** As an operator, I want to diff a broken path against a working one, because the
difference is usually the answer.

#### Acceptance Criteria

1. WHEN a reference source and destination are supplied, THE Comparator SHALL evaluate both paths and
   report only the differences.
2. THE Comparator SHALL diff route entries, NACL entries, security group rules, firewall rule matches,
   and host firewall allowlists.
3. WHEN both paths are identical at every cloud Layer but differ in observed behaviour, THE Comparator
   SHALL identify the host Layers as the remaining explanation.
4. WHEN a Layer abstains for one path and is evaluated for the other, THE Comparator SHALL report that
   Layer's comparison as incomplete.

### Requirement 11: Snapshot Diffing

**User Story:** As an operator, I want to see what changed between two collections, so I can tie a
breakage to a change.

#### Acceptance Criteria

1. WHEN given two Snapshots, THE NetPath_System SHALL report added, removed, and modified resources.
2. THE NetPath_System SHALL group differences by resource type and by account and region.
3. WHEN the two Snapshots have differing schema versions, THE NetPath_System SHALL report that
   comparison may be incomplete.

### Requirement 12: Declared Flow Testing

**User Story:** As an operator, I want expected reachability asserted in CI, so a regression fails a
build rather than a page.

#### Acceptance Criteria

1. THE NetPath_System SHALL accept a file declaring expected Flows, each with an expected verdict.
2. WHEN an actual verdict differs from its expected verdict, THE NetPath_System SHALL report the Flow,
   both verdicts, and the deciding Citation.
3. WHEN any declared Flow fails, THE NetPath_System SHALL exit `1`.
4. WHEN a declared Flow evaluation abstains, THE NetPath_System SHALL report it as inconclusive and
   SHALL NOT count it as a pass.

### Requirement 13: Verification Against Reachability Analyzer

**User Story:** As an operator, I want the model's answers cross-checked against the provider's own
analyzer, so I can trust it.

#### Acceptance Criteria

1. WHEN verification is requested for a same-region Flow, THE Verifier SHALL run an AWS Reachability
   Analyzer analysis and compare its result with the engine verdict.
2. WHEN the verdicts agree, THE Verifier SHALL report agreement and cite both sources.
3. WHEN the verdicts disagree, THE Verifier SHALL report the disagreement prominently and SHALL NOT
   silently prefer either.
4. THE Verifier SHALL state that Reachability Analyzer analyses are billable and, for TCP over a
   transit gateway route table, evaluate forward traffic only.
5. WHERE a Flow crosses a region boundary, THE Verifier SHALL report that no single analyzer run covers
   the path.

### Requirement 14: Verdict Reporting

**User Story:** As an operator, I want an actionable verdict plus evidence I can verify myself.

#### Acceptance Criteria

1. THE Correlator SHALL report exactly one primary blocking Layer, or state that no blocker was found.
2. THE Formatter SHALL render three distinct sections: the blocking Layer with Citations, the Layers
   that passed, and the Abstentions with reasons.
3. THE Formatter SHALL emit human-readable text by default, and JSON or markdown on request.
4. THE Formatter SHALL include the rule group, priority, and SID for every firewall decision.
5. THE Formatter SHALL render markdown suited to low-token consumption, truncating repeated rows beyond
   a configured limit and stating the truncation.
6. WHEN a verdict rests on an Abstention, THE Formatter SHALL state that the verdict is not
   authoritative.
7. THE Formatter SHALL NOT emit credential material or secret values.

### Requirement 15: Guardrails

**User Story:** As an operator, I want to run this against production with no risk of change.

#### Acceptance Criteria

1. THE Guardrail_Enforcer SHALL define an explicit allowlist of permitted AWS API actions and reject
   any action absent from it.
2. THE Guardrail_Enforcer SHALL define an explicit allowlist of permitted host commands and reject any
   command absent from it.
3. THE Guardrail_Enforcer SHALL reject command arguments containing shell metacharacters permitting
   chaining or redirection.
4. WHEN a rejection occurs, THE Guardrail_Enforcer SHALL return an error naming the rejected action or
   command.
5. THE NetPath_System SHALL interpolate no unvalidated input into a host command, and SHALL invoke host
   commands as argument lists rather than shell strings.

### Requirement 16: Interfaces

**User Story:** As an operator, I want this in a terminal, in CI, and available to an agent, from one
implementation.

#### Acceptance Criteria

1. THE NetPath_System SHALL ship as a single statically linked binary with no runtime dependency
   beyond itself.
2. THE NetPath_System SHALL expose a CLI usable with no agent or MCP client present.
3. THE NetPath_System SHALL expose an MCP server over stdio presenting the same capability set.
4. THE CLI and THE MCP server SHALL invoke one shared set of internal operations, with no duplicated
   orchestration logic.
5. THE JSON output schema SHALL be stable enough to assert against in tests.
6. THE CLI SHALL exit with the codes defined in the cross-cutting semantics.

### Requirement 17: Environment Neutrality

**User Story:** As a maintainer publishing this tool, I want no trace of any private network in the
repository, so it is safe to share and useful to anyone.

#### Acceptance Criteria

1. THE repository SHALL contain no real account identifier, credential profile name, hostname, or
   routable address range belonging to any organisation.
2. THE repository SHALL use only reserved documentation ranges and placeholder account identifiers in
   documentation, examples, fixtures, and tests.
3. THE NetPath_System SHALL NOT hardcode any region, account, profile name, or resource naming
   convention in its logic.
4. THE example configuration SHALL demonstrate the multi-account shape using placeholder values only.
5. THE repository SHALL exclude collected Snapshots from version control, and `.gitignore` SHALL
   prevent their accidental commit.
6. WHEN a Snapshot is written, THE NetPath_System SHALL make no attempt to redact it; Snapshots are
   treated as sensitive artefacts and excluded from sharing by policy rather than by transformation.

### Requirement 18: Documentation and Playbooks

**User Story:** As an operator, I want the tool to teach the method, not just return output.

#### Acceptance Criteria

1. THE repository SHALL document collection, configuration, and a worked end-to-end example.
2. THE repository SHALL document the read-only guarantee and every allowlisted action and command.
3. THE repository SHALL document every condition producing an Abstention.
4. THE repository SHALL provide steering playbooks for at least SSH failure triage, service
   unreachable triage, asymmetric path triage, and comparison against a working host.
5. THE repository SHALL document prior art and how this tool differs from it.

## Out of scope

- Any remediation or configuration change. Read-only without exception.
- IPv6 path evaluation.
- Deep-inspection policy depending on TLS SNI, HTTP Host, or packet payload rather than the 5-tuple.
  Reported as an Abstention.
- Transit gateway policy tables and Connect attachments.
- Packet capture and live traffic inspection.
- Non-Linux host probing, including Windows host firewall evaluation.
- Providers other than AWS. The internal model is provider-neutral so this remains possible, but no
  second collector is in scope.
