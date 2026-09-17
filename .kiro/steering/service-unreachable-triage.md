---
inclusion: manual
---

# Service unreachable triage

For "the service is unreachable" — a client cannot reach a service on a known port, and nobody has yet
established whether the fault is in AWS or on the host.

**Check the listener before you investigate policy.** The listener check is one command. The policy
sweep is routes, NACLs, security groups, and Network Firewall rule groups across every account and
region on the path. Running the expensive one first is the most common way this investigation wastes an
afternoon.

## Why the listener leads

A clean cloud verdict with nothing bound to the port is the single most frequent cause of an
unreachable service. The path permits the traffic, every rule is correct, and the daemon is not running
— or it is running and bound to `127.0.0.1`, which is a listener by every definition except the one
that matters. Both look identical from the client, and both look identical in a report that only reads
cloud configuration.

That is also why `diagnose` probes the host even when every cloud layer reports permitted. "Cloud
clear, host unverified" is a materially different answer from "all clear", and the report keeps them
apart.

## 1. Name the symptom before you run anything

The symptom decides the order, so getting it right is the highest-leverage thing you do. Do not reach
for `connection-refused` because the connection failed — reach for it because the client got a
refusal.

| What the client saw | Symptom to pass | What it tells you |
| --- | --- | --- |
| Immediate refusal, `ECONNREFUSED` | `connection-refused` | A RST came back. The packet arrived and something answered, so the cloud path already carried it. Listener first. |
| Silence, then the client gives up | `timeout` | The packet was discarded with no reply. That is policy behaviour: security group, NACL, or route. Cloud layers first. |
| `EHOSTUNREACH`, ICMP administratively prohibited | `no-route-to-host` | Something chose to reject and said so. Host firewall, then network firewall. |
| Ping works, the port does not | `icmp-ok-tcp-fails` | The host is reachable, so the filter is port-specific. Security group and host firewall. |

A refusal is the case this playbook is written for. It is also the case where the cloud sweep is
provably the wrong place to start: a RST is evidence the packet was delivered.

If you genuinely do not know what the client saw, run without `--symptom`. Layers are then evaluated in
flow order and every one is still reported. Guessing a symptom you did not observe reorders the
investigation around a mechanism that did not happen.

## 2. Run the diagnosis

With a snapshot already collected:

```bash
aws-netpath diagnose \
  --snapshot snapshots/snapshot.json \
  --from 192.0.2.10 --to 10.20.9.40 \
  --proto tcp --port 8443 \
  --symptom connection-refused
```

Without one, collect first — `diagnose` reads a snapshot and never calls AWS for topology:

```bash
aws-netpath collect \
  --profiles account-a,network-hub \
  --regions us-east-1,us-west-2
```

`--output` is omitted because the default, `snapshots/snapshot.json`, is already gitignored: a snapshot
is an unsanitised model of a real network and must not be committed.

Endpoints take an address, a CIDR, an instance ID, or a `Name` tag, so the readable form works too:

```bash
aws-netpath diagnose \
  --snapshot snapshots/snapshot.json \
  --from web-client --to api-server \
  --proto tcp --port 8443 \
  --symptom connection-refused
```

An input matching more than one resource halts with every candidate listed rather than answering for
the wrong one. If the destination's interface is attributed to no instance in the snapshot, the host
layers have no instance to probe and will abstain — pass the instance explicitly, or re-collect.

## 3. Read `host_listener` first, and stop if it decided

Three outcomes, and only the third sends you anywhere else.

**Blocked — you are done.** The finding names what was found instead of the listener you expected:

```plaintext
verdict: BLOCKED at host_listener

blocking layer — host_listener:
  [DENY ] host_listener
         cited: ss -tlnp  command: no process listening on tcp/8443 at 10.20.9.40; tcp/8443 is bound elsewhere: 127.0.0.1:8443 java
```

The near miss is called out deliberately, because a socket on the right port bound to the wrong
address is a different fault from a daemon that is not running, and your next step differs:

- `tcp/8443 is bound elsewhere: 127.0.0.1:8443` — the service is up and bound to loopback. Fix the bind
  address in the application config. No AWS change will help.
- `no tcp listeners reported`, or the port simply absent from the list — the service is not running, or
  is running on a different port than the client dialled. Check the unit and the configured port.

Either way the fix is on the host. Nothing in the security groups, NACLs, routes, or firewall policy is
worth reading yet, and the report will have cleared them anyway.

**Passed — now the policy sweep earns its time.** The listener is bound and covers the address the
client dialled, so the service would answer if the packet reached it. Read the blocking layer the
report names. If it names none and every layer cleared while the client still fails, read the
contradictions section: findings that disagree with the reported symptom are themselves diagnostic, and
the report records the disagreement rather than resolving it.

**Abstained — the layer was not checked.** See below. This is not a pass.

## 4. When the listener check abstains

An abstention means the question was never answered. It is never aggregated as a pass, it never
produces exit `0`, and a verdict resting on one carries a banner saying so — `!!` in text output. Treat
it as an open question, not a cleared layer.

The reasons you will actually hit, all prefixed `host layer unverified:`:

| Reason | What to do |
| --- | --- |
| `the diagnose operation was given no systems manager client, so the host was not probed` | The current state of the CLI and the MCP server: neither opens a Systems Manager client yet, so both host layers abstain on every run. Read the listener by hand, below. |
| `instance is not an ssm-managed linux host: <id> is not registered with ssm`, or the agent ping status or platform is reported | The instance is outside Systems Manager's reach. Install or repair the agent, or accept that this host's layers cannot be read and say so in your conclusion. |
| `destination <input> resolved to <description>, which the snapshot attributes to no instance` | Pass the instance explicitly, or re-collect so the interface is attributed. |
| `listener reports tcp listeners only, and the destination protocol is udp` | By design. UDP has no listening state for `ss -tlnp` to report, so this layer stays unverified for a UDP destination. |
| `could not read the output of ss -tlnp` | Read `ss -tlnp` on the host yourself; the parser refuses to guess at a line it did not understand rather than drop a listener from consideration. |

While the host layers abstain, the listener question is still the cheapest one available — you just ask
it directly rather than through the tool. The command is the same one the prober would have run, and it
is read-only:

```bash
aws ssm start-session --target i-0aaaaaaaaaaaaaaa1
# then, on the host
ss -tlnp
```

Look for a socket on the destination port whose bound address covers the address the client dialled.
`0.0.0.0` covers every IPv4 address on the host, `::` covers both families on a default dual-stack
host, and a specific address covers only itself.

Then say what you found and what you did not. "Cloud layers clear, listener bound and covering the
destination address, host firewall unverified" is a complete and honest report. "All clear" is not.

## 5. Only then, the policy layers

With the listener established, the report's own ordering is the right one to follow: the earliest
blocking layer in flow order is primary, and any later blockers are listed after it, so fixing the
first will not necessarily be enough. Flow order is `resolution`, `route`, `nacl`, `security_group`,
`firewall`, `return_path`, `host_firewall`, `host_listener`.

If the cloud layers all clear and a working host exists for the same service, stop reading rules and
diff the two paths instead — the difference is usually the answer. See the comparison playbook.

## What to hold on to

- The listener check costs one probe. The policy sweep costs an afternoon. Order accordingly.
- A refusal is evidence of delivery. It moves the investigation to the host, not away from it.
- Bound-to-loopback is a listener that will never answer. Read the bound address, not just the port.
- An abstention is an open question. Exit `1`, banner, and never a pass.

## Exit codes

- `0` — permitted, with every layer evaluated. Both halves are required.
- `1` — a blocking layer was found, or the answer was established only in part because a layer could
  not be read. Usable output either way.
- `2` — nothing ran: a missing flag, an unreadable snapshot, or an endpoint matching two resources.
