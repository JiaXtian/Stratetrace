# StrataTrace algorithm and guarantees

## Measurement object

For a source, destination, target traffic class \(\tau\), and short window
\(W\), StrataTrace measures an *observable forwarding behavior graph*. It does
not claim that an observed interface address is a physical router or that one
visible hop is one physical forwarding hop.

Path probes belong to one fixed flow key. Diagnostic variants deliberately
change the flow token and never get spliced into the fixed-flow hop sequence.

## DBP: two experimental axes

DBP separates effects using two axes:

| Fixed flow over time | Flow token variants | Classification |
|---|---|---|
| stable | stable and equal | direct/transparent |
| stable | different signatures | per-flow multipath |
| different responder addresses | any | unstable/dynamic |
| stable responder, intermittent replies | any | intermittent ICMP visibility |
| stable visible boundaries, stable missing interior | no variant reveals the interior | opaque observation gap |
| quoted invoking header differs | any | mutable boundary |

A baseline fixed-flow rapid sweep and one cheap flow canary locate suspicious
regions. CAP then samples only those local regions. Fixed-flow temporal evidence
uses the independent `--temporal-samples` target (three by default); the CAP
sample bound is spent only when an unobservable/intermittent or flow-sensitive
region actually requires cross-flow coverage. `--global-cap` replaces this
trigger policy with one whole-path region.

Timeouts are not responder identities. A sequence such as `A, *, A` therefore
supports `INTERMITTENT`, not `UNSTABLE`. This distinction is necessary because
ICMP error generation is control-plane behavior and may be rate-limited even
while data-plane forwarding continues.

For a short gap, every TTL in the boundary window is repeated. For a long gap,
the baseline covers every TTL once while DBP repeats its two adjacent boundary
pairs and a midpoint sentinel. This bounds cost while retaining explicit
sample-coverage metadata.

## CAP: coverage bound

Let an alternative response behavior have sample probability
\(p \ge p_{min}\). Under independent flow-token sampling, the probability of
missing it in \(n\) complete independent samples is

\[
P_{miss} = (1-p)^n \le (1-p_{min})^n.
\]

The implementation draws flow tokens uniformly without replacement. For a
finite token space, its hypergeometric miss probability is no larger than the
independent-sampling bound above, so the displayed certificate is conservative.

To request \(P_{miss} \le \delta\), CAP uses

\[
n \ge \left\lceil\frac{\log \delta}{\log(1-p_{min})}\right\rceil.
\]

The default \(p_{min}=0.25\), \(\delta=0.10\) requires nine complete samples.
The certificate contains the achieved \(n\) and actual upper bound; if the
hard probe budget prevents nine complete matched bundles, the result is
`BUDGET-LIMITED`, never silently certified.

This is a *detection* guarantee, not a topology-recovery theorem. It says that
an alternative behavior with at least the specified mass is unlikely to have
been entirely missed under the model assumptions. It does not say that rare
paths do not exist.

The bound applies to controlled flow variants only. Fixed-flow repeated
observations are reported as repeatability evidence and deliberately carry no
claim about undiscovered flow-token behavior.

## Probe-cost policy

The first fixed-flow sweep covers the configured maximum TTL. Later baseline
repeats stop at the visible range plus a small configurable tail guard. Within
an adaptive region, fixed-flow repetition stops at `temporal_samples`, while
flow variants continue to the CAP bound only when that experimental axis is
needed. Multiple variant bundles are transmitted in one receive batch, without
changing the sample identifiers or flow tokens, reducing timeout latency while
preserving the coverage calculation.

Persistent quoted-header mutations are treated as a change-point signal. If a
DSCP rewrite first appears at TTL 11 and remains visible at later hops, only the
10–11 neighborhood is a mutation boundary; downstream quotations are evidence
of persistence, not additional rewrite locations.

## Identifiability limit

For two internal mechanisms \(M_1\) and \(M_2\), if every allowed probe \(q\)
has the same response distribution,

\[
P(R\mid q,M_1)=P(R\mid q,M_2),
\]

then no endpoint algorithm using only those responses can distinguish the
mechanisms. StrataTrace therefore reports an opaque behavior class and its
visible boundaries. It names MPLS only when a valid RFC 4950 object is present.

## Probe correlation and flow preservation

For IPv4 UDP:

- source/destination addresses, protocol, and UDP ports remain fixed within a
  flow;
- UDP checksum is zero (legal in IPv4) and therefore fixed;
- the payload contains a session/probe tag;
- IPv4 IP-ID carries the 16-bit probe identifier for routers returning only
  the minimum quotation.

For ICMP Echo:

- identifier and sequence remain fixed within a flow;
- a compensation word keeps the ICMP checksum fixed;
- payload and IP-ID provide correlation.

The first available correlation method is recorded per observation.

## RFC extension trust

The parser honors the RFC 4884 length field and legacy 128-byte layout. It
checks extension version and checksum before consuming objects. Invalid
checksums result in untrusted extension evidence; malformed lengths never
advance beyond the packet buffer. RFC 4950 label entries and RFC 5837
interface objects are retained separately from inferred behavior.
