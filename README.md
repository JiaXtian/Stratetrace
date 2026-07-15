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

- preserves one UDP five-tuple during a fixed-flow sweep;
- sends matched TTL bundles close together to improve temporal coherence;
- uses uniform flow-token variants (without replacement) to distinguish
  per-flow load balancing from same-flow temporal change;
- parses RFC 4884 multipart ICMP, RFC 4950 MPLS label stacks, and RFC 5837
  interface information;
- records address, port, and DSCP/ECN mutation visible in the ICMP quotation;
- returns an auditable coverage certificate rather than an unexplained
  confidence score;
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
.venv/bin/pip install -e .
sudo .venv/bin/stratatrace example.com
```

Raw IPv4 sockets require root on macOS and usually root or `CAP_NET_RAW` on
Linux. StrataTrace fails closed when raw access is unavailable—it does not
silently invoke a flow-inconsistent system traceroute.

Useful examples:

```bash
# Default UDP traffic class and local adaptive coverage
sudo stratatrace example.com

# ICMP Echo traffic class
sudo stratatrace --protocol icmp example.com

# Lower-cost diagnosis
sudo stratatrace --profile fast example.com

# Apply CAP to every TTL (more expensive, path-wide guarantee)
sudo stratatrace --global-cap --min-detectable-prob 0.10 \
  --miss-prob 0.01 example.com

# JSON, including individual observations
sudo stratatrace --json --include-observations example.com
```

The fixed UDP destination port defaults to 33434. If that service is open at
the destination, choose another closed port with `--dport`. UDP checksums are
zero to preserve the flow identity while changing the correlation payload;
this is valid for IPv4 but one reason this release does not claim IPv6 support.

## Reproducible demos without privileges

The scripted backend executes the exact controller and reporting code without
opening sockets:

```bash
make demo-opaque
make demo-ecmp
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
  coverage: CERTIFIED; n=9,
            P(miss behavior with p>=0.25) <=0.0751
```

- `DIRECT`: adjacent fixed-flow TTL observations agree.
- `MULTIPATH`: controlled flow variants produce multiple signatures while the
  fixed-flow signature remains stable.
- `UNSTABLE`: the same fixed flow changes over the measurement window.
- `MUTABLE`: the ICMP quotation reveals changed address, port, or DSCP/ECN fields.
- `OPAQUE`: sampled TTL positions remain unobservable between visible
  boundaries.
- `UNKNOWN`: the evidence or probe budget cannot support a stronger class.

`CERTIFIED` describes *detection coverage*, not the probability that a guessed
physical topology is true. See [docs/ALGORITHM.md](docs/ALGORITHM.md).

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

- IPv4 only; UDP and ICMP Echo traffic classes.
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

These are measurement-model boundaries, not hidden caveats.

## Standards and design basis

- [RFC 4884 — Extended ICMP to Support Multi-Part Messages](https://www.rfc-editor.org/rfc/rfc4884.html)
- [RFC 4950 — ICMP Extensions for MPLS](https://www.rfc-editor.org/rfc/rfc4950.html)
- [RFC 5837 — Interface and Next-Hop Identification](https://www.rfc-editor.org/rfc/rfc5837.html)
- [Paris traceroute publications](https://paris-traceroute.net/publications/)

## Safety

The CLI enforces a hard `--max-probes` budget and bounded pacing. Probe only
targets you are authorized to measure, respect network policy, and avoid the
thorough/global modes at high frequency.
