"""DBP/CAP controller and evidence-to-segment analysis."""

from __future__ import annotations

import random
import socket
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple

from .backend import ProbeBackend
from .model import (
    BoundaryRegion,
    FlowKey,
    HopSummary,
    ProbeObservation,
    ProbeProtocol,
    ProbeSpec,
    ReplyKind,
    SegmentCertificate,
    SegmentSummary,
    SegmentType,
    TraceResult,
)
from .stats import miss_probability_bound, required_samples, validate_probability


@dataclass(frozen=True)
class TraceConfig:
    protocol: ProbeProtocol = ProbeProtocol.UDP
    max_hops: int = 30
    timeout: float = 1.0
    pacing_ms: float = 1.0
    baseline_rounds: int = 2
    canary_flows: int = 1
    global_cap: bool = False
    chunk_size: int = 8
    min_detectable_probability: float = 0.25
    miss_probability: float = 0.10
    max_probes: int = 512
    destination_port: int = 33434
    source_port: Optional[int] = None
    seed: Optional[int] = None
    payload_size: int = 32

    def validate(self) -> None:
        if not 1 <= self.max_hops <= 255:
            raise ValueError("max_hops must be between 1 and 255")
        if not 0.01 <= self.timeout <= 60.0:
            raise ValueError("timeout must be between 0.01 and 60 seconds")
        if not 0.0 <= self.pacing_ms <= 1000.0:
            raise ValueError("pacing_ms must be between 0 and 1000")
        if not 1 <= self.baseline_rounds <= 20:
            raise ValueError("baseline_rounds must be between 1 and 20")
        if not 0 <= self.canary_flows <= 20:
            raise ValueError("canary_flows must be between 0 and 20")
        if not 1 <= self.chunk_size <= 64:
            raise ValueError("chunk_size must be between 1 and 64")
        if not 1 <= self.max_probes <= 100_000:
            raise ValueError("max_probes must be between 1 and 100000")
        if not 1 <= self.destination_port <= 65535:
            raise ValueError("destination_port must be between 1 and 65535")
        if self.source_port is not None and not 1 <= self.source_port <= 65535:
            raise ValueError("source_port must be between 1 and 65535")
        if self.payload_size < 16 or self.payload_size > 1400:
            raise ValueError("payload_size must be between 16 and 1400")
        validate_probability(self.min_detectable_probability, "min_detectable_probability")
        validate_probability(self.miss_probability, "miss_probability")


def resolve_ipv4(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve IPv4 target {target!r}: {exc}") from exc


class TraceController:
    """Run the two StrataTrace mechanisms: DBP and CAP."""

    def __init__(self, backend: ProbeBackend, config: TraceConfig) -> None:
        config.validate()
        self.backend = backend
        self.config = config
        self.random = random.Random(config.seed)
        self.observations: List[ProbeObservation] = []
        self.warnings: List[str] = []
        self.baseline_probe_count = 0
        self._next_sample_id = 1
        self._variant_cache: Dict[int, FlowKey] = {}
        self._used_variant_values: set = set()

    def run(self, target: str) -> TraceResult:
        started_wall = datetime.now(timezone.utc).isoformat()
        started = time.monotonic_ns()
        main_flow = self._main_flow()
        terminal_ttl = self._baseline(main_flow)
        analysis_limit = terminal_ttl or self._last_observed_ttl() or self.config.max_hops
        baseline_answered = any(
            item.answered and item.spec.phase == "baseline-fixed"
            for item in self.observations
        )
        if baseline_answered:
            self._flow_canaries(main_flow, analysis_limit)
            regions = self._find_regions(analysis_limit)
        else:
            regions = []
        required = required_samples(
            self.config.min_detectable_probability, self.config.miss_probability
        )
        if self.config.global_cap and baseline_answered:
            global_region = BoundaryRegion(
                1,
                analysis_limit,
                tuple(range(1, analysis_limit + 1)),
                ("global CAP coverage requested",),
            )
            regions = [global_region]
        for region in regions:
            self._probe_region(region, main_flow, required)
        duration_ms = (time.monotonic_ns() - started) / 1_000_000.0
        reached_ttls = [
            item.spec.ttl
            for item in self.observations
            if item.kind == ReplyKind.DESTINATION and item.spec.flow == main_flow
        ]
        reached = bool(reached_ttls)
        stop_ttl = min(reached_ttls) if reached_ttls else terminal_ttl
        if not regions and baseline_answered:
            self.warnings.append(
                "No ambiguous boundary was found; clear hops remain rapid-sweep observations, "
                "not CAP-certified stable edges."
            )
        hops = self._summarize_hops(stop_ttl or analysis_limit, main_flow)
        segments = self._summarize_segments(regions, hops, required)
        adaptive = len(self.observations) - self.baseline_probe_count
        result = TraceResult(
            target=target,
            destination=self.backend.destination,
            source=self.backend.source,
            protocol=self.config.protocol,
            started_at=started_wall,
            duration_ms=duration_ms,
            reached=reached,
            terminal_ttl=stop_ttl,
            probe_count=len(self.observations),
            baseline_probe_count=self.baseline_probe_count,
            adaptive_probe_count=adaptive,
            hops=hops,
            segments=segments,
            observations=list(self.observations),
            warnings=self.warnings,
            policy={
                "core_mechanisms": [
                    "differential_boundary_probing",
                    "confidence_bounded_adaptive_probing",
                ],
                "min_detectable_probability": self.config.min_detectable_probability,
                "requested_miss_probability": self.config.miss_probability,
                "required_complete_samples": required,
                "max_probes": self.config.max_probes,
                "baseline_rounds": self.config.baseline_rounds,
                "canary_flows": self.config.canary_flows,
                "global_cap": self.config.global_cap,
                "flow_identity": main_flow.token,
            },
        )
        self.backend.close()
        return result

    def _main_flow(self) -> FlowKey:
        if self.config.protocol == ProbeProtocol.UDP:
            source_port = self.config.source_port or self.random.randrange(49152, 65536)
            return FlowKey(
                protocol=ProbeProtocol.UDP,
                source_port=source_port,
                destination_port=self.config.destination_port,
            )
        return FlowKey(
            protocol=ProbeProtocol.ICMP,
            icmp_identifier=self.random.randrange(1, 65536),
        )

    def _variant_flow(self, variant: int, main: FlowKey) -> FlowKey:
        cached = self._variant_cache.get(variant)
        if cached is not None:
            return cached
        if main.protocol == ProbeProtocol.UDP:
            while True:
                source_port = self.random.randrange(49152, 65536)
                if source_port != main.source_port and source_port not in self._used_variant_values:
                    break
            result = FlowKey(
                protocol=main.protocol,
                source_port=source_port,
                destination_port=main.destination_port,
                variant=variant,
            )
            value = source_port
        else:
            while True:
                identifier = self.random.randrange(1, 65536)
                if identifier != main.icmp_identifier and identifier not in self._used_variant_values:
                    break
            result = FlowKey(protocol=main.protocol, icmp_identifier=identifier, variant=variant)
            value = identifier
        self._variant_cache[variant] = result
        self._used_variant_values.add(value)
        return result

    def _new_sample_id(self) -> int:
        value = self._next_sample_id
        self._next_sample_id += 1
        return value

    def _send(self, specs: Sequence[ProbeSpec], baseline: bool = False) -> bool:
        remaining = self.config.max_probes - len(self.observations)
        if len(specs) > remaining:
            self.warnings.append(
                f"Probe budget exhausted with {remaining} slots left; skipped an atomic "
                f"{len(specs)}-probe matched bundle."
            )
            return False
        received = self.backend.send_batch(specs)
        self.observations.extend(received)
        if baseline:
            self.baseline_probe_count += len(received)
        return True

    def _baseline(self, flow: FlowKey) -> Optional[int]:
        terminal_ttl: Optional[int] = None
        for round_index in range(self.config.baseline_rounds):
            round_start = len(self.observations)
            sweep_limit = terminal_ttl or self.config.max_hops
            sample_id = self._new_sample_id()
            for start in range(1, sweep_limit + 1, self.config.chunk_size):
                stop = min(start + self.config.chunk_size - 1, sweep_limit)
                specs = [
                    ProbeSpec(
                        ttl=ttl,
                        flow=flow,
                        phase="baseline-fixed",
                        sample_id=sample_id,
                        payload_size=self.config.payload_size,
                    )
                    for ttl in range(start, stop + 1)
                ]
                if not self._send(specs, baseline=True):
                    return terminal_ttl
                terminals = [item.spec.ttl for item in self.observations[-len(specs) :] if item.terminal]
                if terminals:
                    observed_terminal = min(terminals)
                    terminal_ttl = (
                        observed_terminal
                        if terminal_ttl is None
                        else min(terminal_ttl, observed_terminal)
                    )
                    break
            round_observations = self.observations[round_start:]
            if round_index == 0 and not any(item.answered for item in round_observations):
                self.warnings.append(
                    "No ICMP response was received during the first complete fixed-flow "
                    "sweep. DBP/CAP was skipped because no visible boundary exists to "
                    "analyze. Check VPN/TUN routing, host/network firewalls, raw-socket "
                    "packet format, and target reachability."
                )
                break
        return terminal_ttl

    def _flow_canaries(self, main_flow: FlowKey, limit: int) -> None:
        """Cheap differential sweeps that trigger local CAP when they disagree.

        These canaries are deliberately not a completeness certificate. Users
        who need a path-wide guarantee can select ``global_cap``.
        """

        for variant in range(1, self.config.canary_flows + 1):
            sample_id = self._new_sample_id()
            flow = self._variant_flow(variant, main_flow)
            for start in range(1, limit + 1, self.config.chunk_size):
                stop = min(start + self.config.chunk_size - 1, limit)
                specs = [
                    ProbeSpec(
                        ttl=ttl,
                        flow=flow,
                        phase="canary-varied",
                        sample_id=sample_id,
                        payload_size=self.config.payload_size,
                    )
                    for ttl in range(start, stop + 1)
                ]
                if not self._send(specs, baseline=True):
                    return

    def _last_observed_ttl(self) -> Optional[int]:
        values = [item.spec.ttl for item in self.observations if item.answered]
        return max(values) if values else None

    def _find_regions(self, limit: int) -> List[BoundaryRegion]:
        by_ttl: DefaultDict[int, List[ProbeObservation]] = defaultdict(list)
        canary_by_ttl: DefaultDict[int, List[ProbeObservation]] = defaultdict(list)
        for item in self.observations:
            if item.spec.phase == "baseline-fixed" and item.spec.ttl <= limit:
                by_ttl[item.spec.ttl].append(item)
            elif item.spec.phase == "canary-varied" and item.spec.ttl <= limit:
                canary_by_ttl[item.spec.ttl].append(item)
        suspicious: Dict[int, List[str]] = {}
        for ttl in range(1, limit + 1):
            samples = by_ttl.get(ttl, [])
            responders = {item.responder for item in samples if item.responder}
            reasons = []
            if samples and any(not item.answered for item in samples):
                reasons.append("missing response")
            if len(responders) > 1:
                reasons.append("same-flow temporal variation")
            if any(item.mutations for item in samples):
                reasons.append("quoted-header mutation")
            fixed_primary = Counter(item.responder for item in samples if item.responder).most_common(1)
            fixed_address = fixed_primary[0][0] if fixed_primary else None
            canary_addresses = {
                item.responder for item in canary_by_ttl.get(ttl, []) if item.responder
            }
            if canary_addresses and (len(canary_addresses) > 1 or fixed_address not in canary_addresses):
                reasons.append("flow-sensitive response")
            if any(not item.answered for item in canary_by_ttl.get(ttl, [])) and fixed_address:
                reasons.append("flow-sensitive loss")
            if reasons:
                suspicious[ttl] = reasons
        if not suspicious:
            return []
        groups: List[List[int]] = []
        for ttl in sorted(suspicious):
            if not groups or ttl > groups[-1][-1] + 1:
                groups.append([ttl])
            else:
                groups[-1].append(ttl)
        regions = []
        for group in groups:
            first = max(1, group[0] - 1)
            last = min(limit, group[-1] + 1)
            if last - first + 1 <= 7:
                probe_ttls = tuple(range(first, last + 1))
            else:
                midpoint = (first + last) // 2
                probe_ttls = tuple(sorted({first, first + 1, midpoint, last - 1, last}))
            reasons = tuple(sorted({reason for ttl in group for reason in suspicious[ttl]}))
            regions.append(BoundaryRegion(first, last, probe_ttls, reasons))
        return regions

    def _probe_region(self, region: BoundaryRegion, main_flow: FlowKey, required: int) -> None:
        existing_fixed = self._complete_sample_count(region.probe_ttls, variant=False)
        for _ in range(max(0, required - existing_fixed)):
            sample_id = self._new_sample_id()
            specs = [
                ProbeSpec(
                    ttl=ttl,
                    flow=main_flow,
                    phase="dbp-fixed",
                    sample_id=sample_id,
                    payload_size=self.config.payload_size,
                )
                for ttl in region.probe_ttls
            ]
            if not self._send(specs):
                return
        existing_varied = self._complete_sample_count(region.probe_ttls, variant=True)
        for variant in range(existing_varied + 1, required + 1):
            sample_id = self._new_sample_id()
            flow = self._variant_flow(variant, main_flow)
            specs = [
                ProbeSpec(
                    ttl=ttl,
                    flow=flow,
                    phase="dbp-varied",
                    sample_id=sample_id,
                    payload_size=self.config.payload_size,
                )
                for ttl in region.probe_ttls
            ]
            if not self._send(specs):
                return

    def _complete_sample_count(self, ttls: Sequence[int], variant: bool) -> int:
        expected = set(ttls)
        sample_ttls: DefaultDict[int, set] = defaultdict(set)
        for item in self.observations:
            if bool(item.spec.flow.variant) == variant:
                sample_ttls[item.spec.sample_id].add(item.spec.ttl)
        return sum(expected.issubset(values) for values in sample_ttls.values())

    def _summarize_hops(self, limit: int, main_flow: FlowKey) -> List[HopSummary]:
        result = []
        for ttl in range(1, limit + 1):
            samples = [
                item
                for item in self.observations
                if item.spec.ttl == ttl and item.spec.flow == main_flow
            ]
            counts = Counter(item.responder for item in samples if item.responder)
            primary = counts.most_common(1)[0][0] if counts else None
            rtts = sorted(item.rtt_ms for item in samples if item.rtt_ms is not None)
            labels = {
                label
                for item in samples
                if item.extensions
                for label in item.extensions.mpls_labels
            }
            interfaces = {
                interface
                for item in samples
                if item.extensions
                for interface in item.extensions.interfaces
            }
            mutations = sorted({mutation for item in samples for mutation in item.mutations})
            sent = len(samples)
            answered = sum(item.answered for item in samples)
            result.append(
                HopSummary(
                    ttl=ttl,
                    primary=primary,
                    responders=tuple(counts.most_common()),
                    sent=sent,
                    answered=answered,
                    loss_rate=(sent - answered) / sent if sent else 1.0,
                    rtt_min_ms=rtts[0] if rtts else None,
                    rtt_median_ms=statistics.median(rtts) if rtts else None,
                    rtt_max_ms=rtts[-1] if rtts else None,
                    mpls_labels=tuple(sorted(labels, key=lambda item: (item.label, item.ttl))),
                    interfaces=tuple(sorted(interfaces, key=lambda item: (item.role, item.ifindex or -1))),
                    mutations=tuple(mutations),
                )
            )
        return result

    def _summarize_segments(
        self, regions: Sequence[BoundaryRegion], hops: Sequence[HopSummary], required: int
    ) -> List[SegmentSummary]:
        special = [self._classify_region(region, hops, required) for region in regions]
        covered_edges = set()
        for region in regions:
            covered_edges.update(range(region.first_ttl, region.last_ttl))
        direct = []
        for ttl in range(1, len(hops)):
            left = hops[ttl - 1]
            right = hops[ttl]
            if ttl in covered_edges or not left.primary or not right.primary:
                continue
            samples = min(left.sent, right.sent)
            bound = miss_probability_bound(self.config.min_detectable_probability, samples)
            direct.append(
                SegmentSummary(
                    type=SegmentType.DIRECT,
                    first_ttl=ttl,
                    last_ttl=ttl + 1,
                    ingress=left.primary,
                    egress=right.primary,
                    fixed_outcomes=((f"{left.primary}->{right.primary}", samples),),
                    varied_outcomes=(),
                    empirical_stability=1.0 if samples else None,
                    certificate=SegmentCertificate(
                        sample_count=samples,
                        min_detectable_probability=self.config.min_detectable_probability,
                        miss_probability_bound=bound,
                        requested_miss_probability=self.config.miss_probability,
                        certified=samples >= required,
                    ),
                    reasons=("adjacent TTL responses from the fixed target flow",),
                )
            )
        return sorted(direct + special, key=lambda item: (item.first_ttl, item.last_ttl))

    def _classify_region(
        self, region: BoundaryRegion, hops: Sequence[HopSummary], required: int
    ) -> SegmentSummary:
        fixed = [
            item
            for item in self.observations
            if item.spec.ttl in region.probe_ttls and not item.spec.flow.variant
        ]
        varied = [
            item
            for item in self.observations
            if item.spec.ttl in region.probe_ttls and item.spec.flow.variant
        ]
        fixed_signatures = self._sample_signatures(fixed, region.probe_ttls)
        varied_signatures = self._sample_signatures(varied, region.probe_ttls)
        fixed_counts = Counter(fixed_signatures.values())
        varied_counts = Counter(varied_signatures.values())
        fixed_stability = (
            fixed_counts.most_common(1)[0][1] / len(fixed_signatures)
            if fixed_signatures
            else None
        )
        always_missing = []
        for ttl in region.probe_ttls:
            samples = [item for item in fixed + varied if item.spec.ttl == ttl]
            if samples and all(not item.answered for item in samples):
                always_missing.append(ttl)
        fixed_variation = len(fixed_counts) > 1
        varied_variation = len(varied_counts) > 1
        varied_responder_multipath = any(
            len(
                {
                    item.responder
                    for item in varied
                    if item.spec.ttl == ttl and item.responder is not None
                }
            )
            > 1
            for ttl in region.probe_ttls
        )
        mutations = sorted({mutation for item in fixed + varied for mutation in item.mutations})
        fully_answered = bool(fixed and varied) and all(item.answered for item in fixed + varied)
        labels = [
            label
            for item in fixed + varied
            if item.extensions
            for label in item.extensions.mpls_labels
        ]

        reasons = list(region.reasons)
        if fixed_variation:
            segment_type = SegmentType.UNSTABLE
            reasons.append("the same flow produced multiple response signatures over time")
        elif varied_responder_multipath:
            segment_type = SegmentType.MULTIPATH
            reasons.append("controlled flow-token variants produced multiple stable signatures")
        elif always_missing and self._has_visible_boundaries(region, hops):
            segment_type = SegmentType.OPAQUE
            reasons.append(
                "one or more sampled TTL positions remained unobservable between visible boundaries"
            )
        elif mutations:
            segment_type = SegmentType.MUTABLE
            reasons.append("the quoted invoking packet differs from the sent flow")
        elif varied_variation:
            segment_type = SegmentType.UNKNOWN
            reasons.append(
                "flow variants changed response/loss behavior without revealing multiple responders"
            )
        elif (
            fully_answered
            and fixed_counts
            and varied_counts
            and set(fixed_counts) == set(varied_counts)
        ):
            segment_type = SegmentType.DIRECT
            reasons.append("fixed and varied flows agreed across the certified TTL window")
        else:
            segment_type = SegmentType.UNKNOWN
            reasons.append("available evidence does not identify a stable behavior class")

        varied_samples = len(varied_signatures)
        bound = miss_probability_bound(self.config.min_detectable_probability, varied_samples)
        explicit = "MPLS (RFC 4950 label-stack evidence)" if labels else None
        if explicit:
            reasons.append("an ICMP extension explicitly carried an MPLS label stack")
        ingress = hops[region.first_ttl - 1].primary if region.first_ttl <= len(hops) else None
        egress = hops[region.last_ttl - 1].primary if region.last_ttl <= len(hops) else None
        return SegmentSummary(
            type=segment_type,
            first_ttl=region.first_ttl,
            last_ttl=region.last_ttl,
            ingress=ingress,
            egress=egress,
            fixed_outcomes=tuple(fixed_counts.most_common()),
            varied_outcomes=tuple(varied_counts.most_common()),
            empirical_stability=fixed_stability,
            certificate=SegmentCertificate(
                sample_count=varied_samples,
                min_detectable_probability=self.config.min_detectable_probability,
                miss_probability_bound=bound,
                requested_miss_probability=self.config.miss_probability,
                certified=varied_samples >= required and bound <= self.config.miss_probability,
            ),
            reasons=tuple(dict.fromkeys(reasons)),
            explicit_mechanism=explicit,
        )

    @staticmethod
    def _sample_signatures(
        observations: Iterable[ProbeObservation], ttls: Sequence[int]
    ) -> Dict[int, str]:
        by_sample: DefaultDict[int, Dict[int, str]] = defaultdict(dict)
        for item in observations:
            by_sample[item.spec.sample_id][item.spec.ttl] = item.responder or "*"
        expected = set(ttls)
        return {
            sample_id: " | ".join(f"{ttl}:{values[ttl]}" for ttl in ttls)
            for sample_id, values in by_sample.items()
            if expected.issubset(values)
        }

    @staticmethod
    def _has_visible_boundaries(region: BoundaryRegion, hops: Sequence[HopSummary]) -> bool:
        return (
            1 <= region.first_ttl <= len(hops)
            and 1 <= region.last_ttl <= len(hops)
            and hops[region.first_ttl - 1].primary is not None
            and hops[region.last_ttl - 1].primary is not None
        )
