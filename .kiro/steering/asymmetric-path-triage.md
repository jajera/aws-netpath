---
inclusion: manual
---

# Asymmetric path triage

Use this when the connection is made and then nothing happens: the TCP handshake completes, an SSH
banner or a TLS `ClientHello` goes out, and the transfer stalls. Small requests may succeed while
large ones hang. Nothing is refused and nothing times out on connect, which is why the usual
policy hunt comes back empty.

That symptom is `connect-then-stall`, and it has exactly two ordinary explanations: the response
comes back a different way from the request, or a packet somewhere on the path is too large to
cross it. Evaluate the return direction first — it is the one a snapshot can answer offline, and
it is the one no forward-direction check will ever find.

## Start here

```bash
aws-netpath diagnose \
  --snapshot snapshots/snapshot.json \
  --from 10.16.1.10 --to 10.32.1.20 \
  --proto tcp --port 22 \
  --symptom connect-then-stall
```

`--symptom connect-then-stall` is what puts the return path first. It maps to the `RETURN_PATH`
layer plus a path MTU check, so both explanations are evaluated in the same run. Every other layer
is still reported — a symptom narrows the search order, it does not limit the search.

Add `--skip-firewall` when the question is purely which way the two directions go; read the caveat
below before trusting a permitted verdict from that run.

## Why the return direction

Routing in AWS is per-direction. Subnet route tables, transit gateway route tables, and attachment
associations are each one-way objects, so a forward path that reaches the destination says nothing
about how the response gets back. The two directions can resolve to different transit gateways,
different attachments, or a different set of next hops entirely.

On its own that is untidy rather than broken — both directions carry traffic, so no layer blocks.
It becomes a stall when the asymmetry crosses something that keeps per-connection state: a Network
Firewall endpoint or inspection VPC, or a NAT gateway. The forward packets build state on one
device, the response arrives at another that has no matching entry, and it is dropped after the
handshake already succeeded. The tool treats an inspection VPC, a firewall endpoint named directly
by a route table, and a NAT gateway as stateful; route tables, transit gateways, and attachments
forward without keeping state.

The comparison is on next hops, not on the resources that chose them. Two directions are supposed
to use different route tables; what they are expected to agree on is the set of components they
resolve to. Order is not compared, since the return direction meets the same components in reverse.

## Reading the report

Four outcomes, in the order they settle the question.

### The return direction is blocked

A blocked return direction with a permitted forward direction is reported as the **primary
blocker**, not as a footnote to a passing forward walk:

```
symptom: connect-then-stall
verdict: BLOCKED at return_path
blocking layer — return_path:
  [DENY ] return_path
         cited: db-rt  return route: vpc route → TGW tgw-hub
         cited: tgw-attach-db  return tgw: entered transit gateway
         cited: hub  return tgw-route: no TGW route to 10.16.1.10
cleared layers:
  [ALLOW] route
         cited: app-rt  route: vpc route → TGW tgw-hub
         ...
note: return direction is blocked at tgw-route hub: no TGW route to 10.16.1.10; the forward
      verdict does not account for the response path
```

The forward direction still shows in cleared layers, which is the point: a forward-only tool would
have called this permitted. Fix the reverse route; there is nothing further to triage.

### The path is asymmetric across a stateful component

Nothing blocks, so the finding arrives as a **probable cause** rather than a verdict, with both
directions' next hops cited:

```
verdict: NO BLOCKER FOUND
observations:
          return_path
         forward and return directions resolve to different next hops: forward traverses
         tgw-hub (transit-gateway) → tgw-attach-app (attachment) → tgw-attach-db (attachment),
         return traverses tgw-hub (transit-gateway) → tgw-attach-db (attachment) →
         tgw-attach-inspect (attachment) → vpc-inspect (inspection-vpc) → tgw-attach-app
         (attachment); only the return direction traverses tgw-attach-inspect (attachment) →
         vpc-inspect (inspection-vpc); the path crosses stateful vpc-inspect (inspection-vpc), so
         the response returns through a device other than the one holding the connection state and
         the connection can establish and then stall
         cited: tgw-attach-db  forward next hop at tgw-route: 10.32.0.0/16 → tgw-attach-db
         cited: tgw-attach-inspect  return next hop at tgw-route: 10.16.0.0/16 → tgw-attach-inspect
         cited: vpc-inspect  return next hop at inspection-vpc: traffic enters inspection VPC via
                TGW (stateful)
         cited: tgw-attach-inspect  return next hop tgw-attach-inspect (attachment) has no
                counterpart in the forward direction, which resolves to tgw-hub (transit-gateway)
                → tgw-attach-app (attachment) → tgw-attach-db (attachment)
probable cause:
          return_path
         symptom connect-then-stall (state or MTU failure) is explained by asymmetric-stateful: ...
  (nothing was shown to block this flow, so this is an explanation to check rather than a verdict)
```

Both chains are cited on purpose: a difference only means something next to what the other
direction resolved to instead, and each difference is cited again on its own naming the opposite
direction. The `(stateful)` marker on a citation is the component that turns the asymmetry into a
stall.

The same finding appears twice by design. Under `observations` it is the raw comparison; under
`probable cause` it is the explanation drawn from it. Both are there so a reader who disagrees with
the promotion still has the evidence. Promotion only happens when a symptom was supplied and no
layer blocked — a layer shown to have dropped the traffic is the cause, and the observation is then
reported alongside it rather than instead of it.

Go and look at the transit gateway route table associated with the destination's attachment, and at
whichever route sends the return traffic through inspection. An inspection route added for one
direction and never mirrored is the usual origin.

### The path is asymmetric with nothing stateful on it

The comparison is reported as an observation and is not promoted to a probable cause. A stateless
path carries a response that comes back another way without noticing, so on its own it explains no
stall. Worth fixing for predictability; keep looking for the actual cause, starting with MTU.

### The two directions agree

The report says so — `forward and return directions resolve to the same next hops`, or `traverse no
gateway: both resolve locally` for a flow inside one VPC. Asymmetry is ruled out, so the stall is a
path MTU problem until shown otherwise.

## Path MTU, the other explanation

The classifier implicates `RETURN_PATH` and path MTU together, because a stall is what both look
like. The MTU check is a large `ping` with fragmentation forbidden, run from the destination host
back to the source. It is the one probe that puts traffic on the wire, and it runs only when a
symptom points at it.

It reports one of three things, and never concludes anything it did not see:

- a full-size payload crossed unfragmented — MTU is ruled out, the asymmetry stands
- the packet was dropped and a path MTU was reported — that explains the stall
- no reply and no fragmentation-needed message — an abstention, because that is equally consistent
  with ICMP being filtered, and calling it an MTU problem would send you to the wrong device

In the current build neither the CLI nor the MCP server opens a Systems Manager client, so both
host layers and this check abstain with `the diagnose operation was given no systems manager
client`. Until that lands, rule MTU out by hand from the destination — a jumbo-frame interface
talking to a 1500-byte path, or a VPN or inspection hop with a smaller MTU, is the shape to look
for.

## What the verdict does not cover

`connect-then-stall` runs are the ones most likely to come back non-authoritative, and the banner
says why:

- **Reverse-direction firewall policy is deliberately not evaluated.** Stateful inspection permits
  the response to an already permitted flow, and the client ephemeral port is not knowable from
  configuration, so a reverse policy verdict would be invented. Where the return path crosses an
  inspection point, `RETURN_PATH` abstains and names it. The routing was still walked to the end,
  so the asymmetry comparison is still valid.
- **The return flow uses every destination port for TCP and UDP**, for the same ephemeral-port
  reason. The report notes this.
- **Host layers abstain** in the current build, as above.
- **`--skip-firewall` records no abstention for the forward direction**, so a permitted verdict from
  that run is a narrower claim than one from a full run.

An abstention is never folded into a pass. A run with nothing blocking but a layer unread exits `1`,
not `0`: `0` means permitted with every layer checked. `2` means the command could not produce an
answer at all — a missing flag, an unreadable snapshot, an endpoint matching two instances.

## Cross-checking against a path that works

If a comparable flow does not stall, diff the two rather than reading one in isolation. The
different next hop usually falls straight out:

```bash
aws-netpath compare \
  --snapshot snapshots/snapshot.json \
  --from 10.16.1.10 --to 10.32.1.20 \
  --ref-from 10.16.2.11 \
  --proto tcp --port 22 \
  --symptom connect-then-stall
```

`--symptom` describes the failing path only. `--ref-to` defaults to `--to`.

## For agents

Add `--json` for a stable shape, or `--markdown` for a cheaper read. All three renderings come from
one report, so they cannot disagree about what was found: the probable cause section, both hop
chains, and the `has no counterpart in the forward direction` citations are present in each.
