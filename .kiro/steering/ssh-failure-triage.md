---
inclusion: manual
---

# SSH failure triage

Use this when `ssh` to a host will not connect and you have a snapshot to ask questions of. The
method is symptom-first: the error the client printed is the strongest evidence available before any
configuration is read, because different errors are produced by different halves of the stack.

Every address below is from a reserved range (RFC 1918, or RFC 5737 documentation space) and every
account ID is a placeholder. Substitute your own.

## Step 0 — read the client error exactly

Run the connection again and keep the wording. Do not paraphrase it, and do not accept a second-hand
report of it; "it just hangs" and "connection refused" send the investigation in opposite directions.

```bash
ssh -vvv admin@192.0.2.10
```

Three outcomes matter, and they split on what the far side did with the packet:

| Client error | What the far side did | `--symptom` | Layers checked first |
| --- | --- | --- | --- |
| `Connection refused` | RST returned — something received the packet and answered | `connection-refused` | `HOST_LISTENER`, `HOST_FIREWALL` |
| `Connection timed out` / no output | silent discard — received and said nothing | `timeout` | `SECURITY_GROUP`, `NACL`, `ROUTE` |
| `No route to host` | active rejection — ICMP administratively prohibited on a network that does have a route | `no-route-to-host` | `HOST_FIREWALL`, `FIREWALL` |

Read that middle column as the whole point. A device that **answered** is a device the packet reached,
which clears every cloud layer in front of it by observation rather than by evaluation. A device that
said **nothing** is the signature of a policy that drops: a security group, a NACL, or a missing route.

Two more errors show up on port 22 and are worth naming:

| Client error | `--symptom` | Layers checked first |
| --- | --- | --- |
| ping works, `ssh` does not | `icmp-ok-tcp-fails` | `SECURITY_GROUP`, `HOST_FIREWALL` |
| banner appears, then the session stalls | `connect-then-stall` | `RETURN_PATH`, plus path MTU |

`connect-then-stall` on SSH is not a policy failure — the handshake completed, so no layer blocked it.
Go to the asymmetric path playbook instead of this one.

## Step 1 — diagnose with the symptom attached

Pass the symptom. The layers that failure implicates are evaluated first, which is usually the
shortest route to the answer, and every other layer is still reported — a symptom narrows the search
rather than limiting it.

Refused:

```bash
aws-netpath diagnose \
  --snapshot snapshots/snapshot.json \
  --from 10.0.1.10 --to 10.0.2.20 \
  --proto tcp --port 22 \
  --symptom connection-refused
```

Timed out:

```bash
aws-netpath diagnose \
  --snapshot snapshots/snapshot.json \
  --from 10.0.1.10 --to 10.0.2.20 \
  --proto tcp --port 22 \
  --symptom timeout
```

No route to host:

```bash
aws-netpath diagnose \
  --snapshot snapshots/snapshot.json \
  --from 10.0.1.10 --to 10.0.2.20 \
  --proto tcp --port 22 \
  --symptom no-route-to-host
```

Endpoints accept an address, a CIDR, an instance ID, or a `Name` tag, so the readable form works too:

```bash
aws-netpath diagnose --snapshot snapshots/snapshot.json \
  --from bastion --to app-server --proto tcp --port 22 --symptom connection-refused
```

An input matching more than one resource halts with every candidate listed. Disambiguate with the
instance ID rather than guessing which one was meant.

## Step 2 — read the report in the order it is written

`diagnose` prints three sections, and each answers a different question.

**Blocking layer.** The earliest blocking layer in flow order, with the rule, priority, and SID that
decided it. This is the fix: a specific line in a specific construct.

**Cleared layers.** What was evaluated and permits the flow. Useful as much for ruling out a theory as
for confirming one.

**Abstentions.** Layers that could not be established, each with a reason, plus a statement of whether
an abstention could have changed the verdict. An abstention is never a pass. "Cloud clear, host
unverified" is a materially different answer from "all clear", and the exit code says so: `0` means
nothing blocks the flow *and* every layer was checked.

Host layers are probed over Systems Manager. On an unmanaged instance, or where a command cannot be
delivered, they abstain — see step 4.

## Step 3 — reconcile the finding against the symptom

Now check that the report and the client error tell the same story. Where they do not, the
contradiction is itself diagnostic and `diagnose` reports it rather than resolving it.

| Symptom | Report says | Reading |
| --- | --- | --- |
| `connection-refused` | `HOST_LISTENER` blocked | sshd is not listening, or not on 22, or bound to the wrong address. Confirmed. |
| `connection-refused` | `HOST_FIREWALL` blocked | the host rejected rather than dropped. Confirmed. |
| `connection-refused` | every layer passed, host layers abstained | the RST came from the host and the host was not read. Get SSM working, then re-run — the answer is behind the abstention. |
| `connection-refused` | a cloud layer blocked | contradiction. A dropped packet cannot produce a RST, so either the tested 5-tuple is not the one that failed, or the snapshot predates a change. Check `--from`, `--port`, and the snapshot timestamp. |
| `timeout` | `SECURITY_GROUP` / `NACL` / `ROUTE` blocked | confirmed. Silence is what a drop looks like. |
| `timeout` | every cloud layer passed | the drop is at the host, or the return direction never made it back. Continue at step 4. |
| `no-route-to-host` | `HOST_FIREWALL` blocked | firewalld rejected with ICMP administratively prohibited. Confirmed. |
| `no-route-to-host` | `FIREWALL` blocked | a Network Firewall rule with a reject action. Confirmed. |
| `no-route-to-host` | `ROUTE` blocked | read this carefully. A genuinely missing route usually produces a local error rather than an ICMP rejection from the path, so check whether the client is reporting its own missing route. |

## Step 4 — when the cloud is clear and it still fails

This is the case the tool exists for. AWS configuration can be entirely correct while the host refuses
the connection, and no cloud API can see that.

The host layers report on the listener and on firewalld:

- **listener** — `ss -tlnp`. No socket on 22 explains `connection-refused` outright.
- **firewalld rich rules** — `firewall-cmd --zone=<zone> --list-rich-rules`. A source absent from the
  allowlist explains `no-route-to-host`.
- **firewalld services** — `firewall-cmd --zone=<zone> --list-services`. A named `ssh` service may be
  what permits 22, so an apparently missing rich rule is not conclusive on its own.
- **local route** — `ip route get <dst>`. An unexpected egress interface.

Allowlist matching is by network containment, not string equality. An entry of `198.51.100.128/26`
covers a source of `198.51.100.190` even though the two strings share nothing, and this is a real
failure mode: a host provisioned from an older template carries a narrower allowlist than the current
one, and eyeballing the strings misses that the current entry should have covered the source.

If the host layers abstain because the instance is unmanaged or SSM cannot deliver a command, say so
in the ticket. Do not report the flow as permitted. The report is explicit that the host was not read,
and that wording is worth carrying forward.

## Step 5 — diff against a host that works

When a second source reaches the same service and this one does not, the difference between the two
paths is usually the whole answer:

```bash
aws-netpath compare \
  --snapshot snapshots/snapshot.json \
  --from 10.0.1.10 --to 10.0.2.20 \
  --ref-from 10.0.1.11 \
  --proto tcp --port 22 \
  --symptom connection-refused
```

Only the differences are reported. Where every cloud layer matches but the behaviour does not, the
report names the host layers as the remaining explanation. Where a layer abstains on one side, that
comparison is reported as incomplete rather than as a match. `--symptom` describes the failing path
only; the reference path is the one that works, so there is no observed failure on it to classify.

See the comparison playbook for the full workflow.

## Step 6 — tie it to a change

If SSH worked yesterday, ask what moved rather than what is wrong:

```bash
aws-netpath diff --from snapshot-before.json --to snapshot-after.json
```

No path is walked and no policy is evaluated, which makes this the cheapest question in the tool.

## Step 7 — codify the answer

Once the flow is fixed, declare it so the same page does not recur:

```yaml
flows:
  - name: bastion must reach app over ssh
    from: 10.0.1.10
    to: 10.0.2.20
    proto: tcp
    port: 22
    expect: permitted

  - name: workloads must not reach the management range over ssh
    from: 10.0.1.10
    to: 192.0.2.10
    proto: tcp
    port: 22
    expect: blocked
```

```bash
aws-netpath test --snapshot snapshots/snapshot.json --flows flows.yaml
```

Exit `1` on any failure, with the deciding citation attached. A flow whose endpoints cannot be
resolved, or that abstains, is inconclusive — never a pass.

## Ordering, in one line each

1. Read the client error verbatim; it is evidence, not colour.
2. Refused means answered — lead with the host.
3. Timed out means silence — lead with security groups, NACLs, routes.
4. No route to host means rejected on purpose — lead with the host firewall, then Network Firewall.
5. Reconcile the report against the symptom, and treat a contradiction as a finding.
6. Never read an abstention as a pass.
