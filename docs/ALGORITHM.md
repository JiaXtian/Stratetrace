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
| changing | any | unstable/dynamic |
| stable visible boundaries, stable missing interior | no variant reveals the interior | opaque observation gap |
| quoted invoking header differs | any | mutable boundary |

A baseline fixed-flow rapid sweep and one cheap flow canary locate suspicious
regions. CAP then samples only those local regions. `--global-cap` replaces
this trigger policy with one whole-path region.

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
