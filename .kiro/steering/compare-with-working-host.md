---
inclusion: manual
---

# Playbook: compare with a working host

Two hosts, one service, one of them connects. Whatever the two paths share cannot be the cause, so the
difference between them is the answer. That subtraction is what `aws-netpath compare` does, and it is
the first thing to reach for whenever a sibling path exists — not the fallback after a full diagnosis
went nowhere. A diagnosis explains one path across eight layers. A comparison deletes every layer the
two paths agree on and hands back what is left, which is usually one rule.

Reach for this when any of these is true:

- another host in the same subnet, or another subnet in the same VPC, reaches the same service
- the same client reaches a sibling service on the same port
- the path used to work from somewhere and still does from there
- a diagnosis came back permitted at every cloud layer and the client still fails

If no path works, there is nothing to subtract: diagnose instead.

## Step 1 — pick the reference path

The reference is a path believed to work, evaluated against the **same snapshot** as the failing path.
One snapshot matters: both paths go through one pipeline, so a difference is a configuration
difference rather than an artefact of two collections taken minutes apart.

Pick the closest working sibling, not the most convenient one. Every axis the two paths differ on
becomes a candidate difference in the report, so a reference in another account and another region
produces a long report that says little. In descending order of usefulness:

1. another source in the same subnet, same destination, same port — differs by ENI and security group only
2. another source in the same VPC, same destination and port
3. same source, sibling destination in the same subnet — use `--ref-to`
4. anything further away, accepting the noise

## Step 2 — run the comparison

The ordinary shape is two sources, one service, one of them working. `--ref-to` defaults to `--to`, so
it is omitted:

```bash
aws-netpath compare --snapshot snapshots/snapshot.json \
  --from 10.0.1.11 --to 10.0.2.20 \
  --ref-from 10.0.1.10 \
  --proto tcp --port 443
```

Two destinations, one source — the sibling-service shape — names both:

```bash
aws-netpath compare --snapshot snapshots/snapshot.json \
  --from 10.0.1.10 --to 10.0.2.21 \
  --ref-from 10.0.1.10 --ref-to 10.0.2.20 \
  --proto tcp --port 443
```

`--symptom` describes the **failing path only**. The reference path works, so there is no observed
failure on it to classify. Supply it whenever the client error is known — it is the only way to
establish a behaviour difference when both paths evaluate the same (see step 4):

```bash
aws-netpath compare --snapshot snapshots/snapshot.json \
  --from 10.0.1.10 --to 10.0.2.20 --ref-from 10.0.1.11 \
  --proto tcp --port 22 --symptom connection-refused
```

Flags, all of them already implemented — do not invent others:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--snapshot` | required | Path to a snapshot file |
| `--from`, `--to` | required | Failing path source and destination |
| `--ref-from` | required | Reference path source, the one that works |
| `--ref-to` | `--to` | Reference path destination |
| `--proto` | `tcp` | `tcp`, `udp`, or `icmp` |
| `--port` | | Destination port, required for `tcp` and `udp` |
| `--symptom` | | `connection-refused`, `no-route-to-host`, `timeout`, `connect-then-stall`, `icmp-ok-tcp-fails` — failing path only |
| `--skip-firewall` | | Routing and NACLs only, applied to **both** paths |
| `--json`, `--markdown` | | Render as JSON or markdown instead of text |

Nothing here calls AWS. Comparison is offline over the snapshot, so it costs nothing and can be run as
many times as there are candidate reference paths.

## Step 3 — read only the differences

What gets diffed entry by entry:

- **route entries** — which route matched, and its target
- **NACL entries** — the numbered entry that decided, in both directions
- **security group rules** — the ingress and egress rules that matched, or the absence of a match
- **firewall rule matches** — the rule group, priority, and SID that decided
- **host firewall allowlists** — the allowlist entry, where a host was probed

Endpoint resolution is compared by verdict only. The endpoints differ by construction — that is the
premise of the comparison, not a finding.

The report has the same three sections as a diagnosis, filled with what a comparison found. Read the
first, and stop if it answers the question:

```text
path: failing path 10.0.1.11 -> 10.0.2.20: blocked at security_group
path: reference path 10.0.1.10 -> 10.0.2.20: permitted
verdict: DIFFERS at security_group
differences:
  [DIFFERS] security_group
         security_group blocks the failing path and permits the reference path (1 entry only on the failing path, 2 entries only on the reference path)
         cited: failing only: sg-0123456789abcdef2  no matching egress rule (1 recorded)
         cited: reference only: sg-0123456789abcdef0  egress allow tcp/443 to 10.0.0.0/16
         cited: reference only: sg-0123456789abcdef1  ingress allow tcp/443 from 10.0.1.0/24
  (the failing path is blocked at security_group while the reference path is permitted)
matched layers:
  [MATCH] resolution
  (entries omitted: a comparison reports differences only)
```

Every difference names both sides: the entry that was found, and the side it is missing from. "The
security groups differ" is not actionable; `sg-0123456789abcdef2` having no egress rule for tcp/443
while `sg-0123456789abcdef0` has one is a change request.

**Matched layers are named and nothing more.** Their entries are deliberately omitted. A comparison
that reprints both paths in full hands you the same haystack twice.

## Step 4 — when every cloud layer matches

The interesting outcome. Same routes, same NACL entries, same security group rules, same firewall
rules, and one host still fails. The cloud configuration cannot be what separates the two paths, so
the host layers are the remaining explanation — and `compare` says so under its own heading:

```text
path: failing path 10.0.1.10 -> 10.0.2.20: permitted, symptom connection-refused
path: reference path 10.0.1.10 -> 10.0.2.20: permitted
verdict: IDENTICAL at every layer compared
remaining explanation:
          host_firewall, host_listener
         the failing and reference paths meet the same entries at every compared cloud layer: route, security_group, return_path, so the cloud configuration is not what separates them; host_firewall, host_listener are the remaining explanation (symptom connection-refused was observed on the failing path, which no layer accounts for)
  (nothing here was shown to block the traffic; these are the layers the comparison does not rule out)
```

Read that section for what it is. Nothing there was shown to block anything. What was shown is that
the cloud configuration is identical, which makes `host_firewall` and `host_listener` the only
remaining candidates. That is a direction, not a verdict, and the next move is a host probe rather
than a change to a security group.

The section only appears when a behaviour difference was **established**, in one of two ways:

- the engine reached different verdicts on the two paths, or
- `--symptom` reported a failure on the failing path that no layer accounts for

Calling one path "failing" on the command line is a premise, not evidence. With identical cloud layers
and no symptom, the report says so instead of guessing:

```text
note: the cloud layers match and neither verdict differs, so no behaviour difference was established; supply the symptom observed on the failing path to have the remaining layers named
```

That note is the instruction: rerun with `--symptom`.

## Step 5 — respect the incomplete comparisons

A layer that abstained on one side, or that one walk never reached, is reported as **incomplete**.
Never silently equal, never a difference. It could be identical or it could be the whole cause, and
both readings would be guesses:

```text
incomplete comparisons:
  [INCOMPLETE] route
         route was evaluated for the reference path and not reached on the failing path, so the two cannot be compared here
  [INCOMPLETE] host_firewall
         host_firewall abstained on both paths, so neither was evaluated: failing path: host layer unverified: … the diagnose operation was given no systems manager client, so the host was not probed; reference path: …
!! this comparison is not authoritative: route, return_path, host_firewall, host_listener could not be compared, so a difference there is neither ruled in nor ruled out
```

Consequences worth holding onto:

- **An incomplete cloud layer suppresses the remaining-explanation section.** A layer unread on one
  side has not been shown to match, so the host layers cannot be named as what is left. Fix the gap
  in the snapshot, then rerun.
- **Both sides abstaining is not agreement.** Two unread layers are not a match.
- **"Not reached" is not a pass.** A path blocked early stops there, so the later layers have nothing
  to compare against. Resolve the earlier difference and rerun to see the rest.
- **A non-authoritative comparison stays exit 1** even when no difference was found, because
  "identical everywhere" was never established.

## Exit codes

| Code | Meaning here |
| --- | --- |
| 0 | No difference found and every layer was compared |
| 1 | A difference was found, or a comparison was incomplete — usable output either way |
| 2 | Usage error, unreadable snapshot, or an endpoint matching more than one resource |

A difference is the finding this command exists to produce, so it is signalled the way a blocked flow
is. In CI, exit 1 means read the report.

## Loop

Comparison is cheap and offline, so iterate:

1. difference found at a cloud layer → that is the answer, cite the entry and stop
2. identical cloud layers, behaviour difference established → probe the named host layers
3. identical cloud layers, no behaviour difference established → rerun with `--symptom`
4. incomplete at a cloud layer → close the collection gap, rerun
5. reference path too distant, report too noisy → pick a closer sibling and rerun

## Conventions

Addresses and identifiers in this playbook are reserved documentation values: RFC 1918 ranges
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), the RFC 5737 documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), and placeholder account identifiers such as `111122223333`. Keep
it that way in anything committed here: snapshots are sensitive artefacts, excluded from version
control rather than redacted.
