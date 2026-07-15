# StrataTrace

StrataTrace is a working IPv4 traceroute that treats the path as observable
data-plane behavior, not as an unquestionable list of router IPs. It has two
core mechanisms:

1. **Differential Boundary Probing (DBP)** compares nearly adjacent TTLs on a
   fixed flow, the same flow over time, and controlled flow-token variants. It
   locates boundaries between direct, multipath, unstable, mutable, and
   repeatably unobservable behavior.
2. **Confidence-Bounded Adaptive Probing (CAP)** spends additional probes only
   on ambiguous regions, then stops when a configured detection-coverage bound
   is met or the hard probe budget is exhausted.

It does **not** claim to magically expose a tunnel that emits no differentiating
information. `OPAQUE` has a precise meaning: a repeatable observation gap lies
between two visible boundaries. A protocol such as MPLS is named only when an
ICMP extension supplies explicit evidence.

## Why this is useful

Classic traceroute assigns the same fixed probe count to every TTL and can mix
flows when identifying probes. StrataTrace instead:

- preserves the target traffic-class flow key during a fixed-flow sweep;
- sends matched TTL bundles close together to improve temporal coherence;
- uses uniform flow-token variants (without replacement) to distinguish
  per-flow load balancing from same-flow temporal change;
- parses RFC 4884 multipart ICMP, RFC 4950 MPLS label stacks, and RFC 5837
  interface information;
- records address, port, and DSCP/ECN mutation visible in the ICMP quotation;
- returns an auditable coverage certificate rather than an unexplained
  confidence score;
- separates forwarding-responder changes from intermittent ICMP visibility, so
  control-plane rate limiting is not mislabeled as path instability;
- localizes a persistent quoted-header rewrite to the TTL where its mutation
  profile first changes instead of marking every downstream hop mutable;
- supports TCP SYN path measurement with direct SYN-ACK/RST-ACK termination,
  using a fixed five-tuple and a sequence-based correlation key;
- distinguishes persistent bounded silence from intermittent ICMP visibility,
  and represents an unbounded post-path gap as `SILENT_TAIL` instead of
  falsely calling it an opaque tunnel;
- defaults to a host-like TCP SYN option profile while retaining a bare-SYN
  compatibility profile for controlled A/B diagnosis;
- separates overlapping visibility, mutation, temporal, and multipath evidence
  into independent boundaries while sharing their adaptive probe bundles;
- coalesces independently triggered evidence families when they certify the
  exact same behavior window, retaining every reason without printing a false
  duplicate path event;
- optionally compares raw TCP SYN visibility with a host-kernel TCP connection
  control, kept explicitly outside the measured path graph;
- emits structured JSON for measurement pipelines.

The behavior model is not tied to satellite networks or to MPLS. It applies to
any forwarding domain whose externally visible response changes: ECMP/LAG,
label switching, overlays, middleboxes, tunnels, mobile cores, SD-WAN, and
ordinary IP forwarding. End-host probing still cannot enumerate arbitrary L2
or tunnel internals that expose no information; StrataTrace reports that
identifiability boundary instead of inventing hops.

## Install and run

Python 3.9+ is required; runtime dependencies are zero.

```bash
python3 -m venv .venv
.venv/bin/pip install .
sudo .venv/bin/stratatrace example.com
```

For development on macOS with Python 3.14+, use a non-hidden environment such
as `python3 -m venv venv && venv/bin/pip install -e .`. Python 3.14 skips `.pth`
files carrying macOS's `hidden` flag; an editable install inside `.venv` can
therefore leave a working launcher that cannot import `stratatrace`. Install as
the normal user and use `sudo` only for the probe command.

Raw IPv4 sockets require root on macOS and usually root or `CAP_NET_RAW` on
Linux. StrataTrace fails closed when raw access is unavailable—it does not
silently invoke a flow-inconsistent system traceroute.

Useful examples:

```bash
# Default UDP traffic class and local adaptive coverage
sudo stratatrace example.com

# ICMP Echo traffic class
sudo stratatrace --protocol icmp example.com

# TCP SYN toward the default HTTPS port; SYN-ACK and RST-ACK both confirm reachability
sudo stratatrace --protocol tcp example.com

# Trace the path seen by TCP port 80
sudo stratatrace --protocol tcp --dport 80 example.com

# A/B test a bare TCP SYN if a middlebox treats the default host-like SYN differently
sudo stratatrace --protocol tcp --tcp-syn-profile minimal example.com

# Diagnose raw-SYN silence against the host TCP stack. This completes and
# immediately closes one no-application-data TCP handshake.
sudo stratatrace --protocol tcp --tcp-connect-control example.com

# Lower-cost diagnosis
sudo stratatrace --profile fast example.com

# Apply CAP to every TTL (more expensive, path-wide guarantee)
sudo stratatrace --global-cap --min-detectable-prob 0.10 \
  --miss-prob 0.01 example.com

# JSON, including individual observations
sudo stratatrace --json --include-observations example.com
```

The fixed UDP destination port defaults to 33434. TCP defaults to port 443 and
can target any explicit `--dport`. The default `standard` TCP SYN profile carries
stable MSS, SACK-permitted, timestamp, and window-scale options; `minimal` sends
a bare SYN. Raw TCP path probes do not complete the connection. UDP checksums are zero to preserve the flow
identity while changing the correlation payload; this is valid for IPv4 but one
reason this release does not claim IPv6 support.

The optional `--tcp-connect-control` is deliberately different: it asks the
host kernel to complete and immediately close one TCP connection without
sending application data. A successful connection or refusal is positive
transport evidence, but can still be produced or redirected by a local proxy or
middlebox. The result is reported separately and is never inserted into the raw
traceroute path. The source address used by both modes is compared and a warning
is emitted if they differ.

## Troubleshooting macOS VPN/proxy fake IPs

If a public hostname resolves to `198.18.x.x`, it is not the public server's
address. `198.18.0.0/15` is reserved by IANA for benchmarking and is commonly
used as a synthetic address pool by VPN/proxy TUN implementations. Raw TTL
probes sent to that address cannot reconstruct the original Internet path.

StrataTrace now stops before probing and reports this condition. Correct it by
disabling the VPN/proxy TUN temporarily, or configure both DNS and routing for
the measurement target to bypass fake-IP/TUN handling. Merely using a numeric
public IP is insufficient when its route still points at the TUN interface.

Check the active state on macOS with:

```bash
dscacheutil -q host -a name example.com
route -n get 1.1.1.1
ifconfig | grep -A4 utun
```

`--allow-benchmark-address` is provided only for an intentional isolated RFC
2544 lab. It should not be used to suppress this warning for public targets.

If the launcher exists but reports `ModuleNotFoundError`, repair the virtual
environment with a normal wheel installation as the normal user:

```bash
.venv/bin/python -m pip install --force-reinstall .
.venv/bin/python -c 'import stratatrace; print(stratatrace.__version__)'
```

Do not run `sudo pip install`; only the final raw-socket probe needs `sudo`.

## Reproducible demos without privileges

The scripted backend executes the exact controller and reporting code without
opening sockets:

```bash
make demo-opaque
make demo-ecmp
make demo-realistic
```

Or directly:

```bash
PYTHONPATH=src python3 -m stratatrace \
  --simulate tests/fixtures/unstable.json -m 8 unstable.example
```

## Output semantics

```text
TTL 2-4  OPAQUE  10.0.1.1 => 203.0.113.9
  explicit evidence: MPLS (RFC 4950 label-stack evidence)
  flow coverage: CERTIFIED; n=9/9,
                 P(miss behavior with p>=0.25) <=0.0751
```

- `DIRECT`: adjacent fixed-flow TTL observations agree.
- `MULTIPATH`: controlled flow variants produce multiple signatures while the
  fixed-flow signature remains stable. The output lists responder counts at
  each TTL where branches were directly observed.
- `UNSTABLE`: the same fixed flow produces different responder addresses over
  the measurement window; timeouts alone never trigger this class.
- `INTERMITTENT`: ICMP visibility changes, but every received response still
  identifies the same forwarding responder. This is evidence about response
  behavior, not proof of forwarding loss or route change.
- `MUTABLE`: the ICMP quotation reveals changed address, port, or DSCP/ECN fields.
- `OPAQUE`: sampled TTL positions remain unobservable between visible
  boundaries.
- `SILENT_TAIL`: probes after the last visible responder through the configured
  maximum receive no response. Because there is no visible egress, this is not
  certified as `OPAQUE` and does not identify a tunnel or filtering mechanism.
- `UNKNOWN`: the evidence or probe budget cannot support a stronger class.

`CERTIFIED` is printed only for flow-variant CAP coverage. Mutation and
same-flow temporal observations instead report `fixed-flow evidence` and make
no cross-flow coverage claim. Neither label is the probability that a guessed
physical topology is true. See [docs/ALGORITHM.md](docs/ALGORITHM.md).

When a trace has visible hops but receives no terminal response, the
destination may be silently filtering that traffic class. StrataTrace reports
this as unconfirmed rather than treating the last visible router as the target.
`SILENT_TAIL` records exactly how far probing continued. Run separate TCP, UDP,
and ICMP traces for comparison; the traffic classes are never spliced into one
path.

For TCP, a `SILENT_TAIL` can be further diagnosed with
`--tcp-connect-control`. If the kernel control succeeds while the raw trace
remains silent, the defensible conclusion is protocol/probe-shape or
local-stack/proxy-dependent visibility—not destination unreachability and not a
recoverable sequence of hidden routers.

## Test and verify

```bash
make test
```

The test suite covers packet construction, fixed ICMP checksums, minimum ICMP
quotations, corrupt extension rejection, RFC 4950/RFC 5837 objects, CAP sample
bounds, and end-to-end transparent/ECMP/opaque/unstable scenarios.

On a Linux host with `ip`, `iptables`, and root privileges, run the real
three-hop namespace lab:

```bash
sudo tools/netns_lab.sh
```

It first verifies a transparent route, then suppresses one router's TTL-expired
ICMP replies and verifies that StrataTrace reports a bounded opaque observation
gap.

## Current scope and honest limitations

- IPv4 only; UDP, ICMP Echo, and TCP SYN traffic classes.
- Raw probes use the IPv4 IP-ID as the minimum-quotation correlation key and a
  session tag when the router quotes enough payload. An unusual device hashing
  on IP-ID can still create per-packet variation; StrataTrace will normally
  expose this as instability rather than silently joining false edges.
- A single canary flow is a low-cost trigger, not a path-wide completeness
  proof. Use `--global-cap` when every TTL must receive the configured CAP
  guarantee.
- Independent/stationary sampling assumptions can fail during rapid route
  changes or adversarial hashing. They are printed in JSON certificates.
- No end-host-only tool can distinguish two internal mechanisms that produce
  identical responses to every allowed probe. Lack of RFC 4950 data is never
  interpreted as lack of MPLS.
- Responding interface IPs are not automatically alias-resolved into routers.
- TCP sequence numbers vary to correlate minimum ICMP quotations and direct
  acknowledgements. A device that hashes TCP sequence or IPv4 IP-ID beyond the
  normal five-tuple can still expose per-packet behavior; StrataTrace reports
  the resulting fixed-flow variation rather than hiding it.
- TCP SYN options are intentionally stable within a run. The `standard` profile
  is representative rather than an emulation of the local kernel's exact TCP
  fingerprint; compare `minimal` when diagnosing option-sensitive policy.
- The optional kernel TCP control changes external state by completing a TCP
  handshake. It sends no application data and closes immediately, but should
  only be used against targets you are authorized to contact.

These are measurement-model boundaries, not hidden caveats.

## Standards and design basis

- [RFC 4884 — Extended ICMP to Support Multi-Part Messages](https://www.rfc-editor.org/rfc/rfc4884.html)
- [RFC 4950 — ICMP Extensions for MPLS](https://www.rfc-editor.org/rfc/rfc4950.html)
- [RFC 5837 — Interface and Next-Hop Identification](https://www.rfc-editor.org/rfc/rfc5837.html)
- [RFC 1812 — Requirements for IP Version 4 Routers](https://www.rfc-editor.org/rfc/rfc1812.html)
- [RFC 9293 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293.html)
- [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
- [RFC 2544 — Network Interconnect Device Benchmarking](https://www.rfc-editor.org/rfc/rfc2544.html)
- [Paris traceroute publications](https://paris-traceroute.net/publications/)

## Safety

The CLI enforces a hard `--max-probes` budget and bounded pacing. Probe only
targets you are authorized to measure, respect network policy, and avoid the
thorough/global modes at high frequency.
