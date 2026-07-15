"""DBP/CAP controller and evidence-to-segment analysis."""

from __future__ import annotations

import random
import socket
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
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
    TcpConnectControl,
    TerminationSummary,
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
    temporal_samples: int = 3
    canary_flows: int = 1
    global_cap: bool = False
    chunk_size: int = 8
    adaptive_batch_samples: int = 4
    tail_guard_hops: int = 3
    min_detectable_probability: float = 0.25
    miss_probability: float = 0.10
    max_probes: int = 512
    destination_port: int = 33434
    source_port: Optional[int] = None
    tcp_syn_profile: str = "standard"
    tcp_connect_control: bool = False
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
        if not 2 <= self.temporal_samples <= 20:
            raise ValueError("temporal_samples must be between 2 and 20")
        if not 0 <= self.canary_flows <= 20:
            raise ValueError("canary_flows must be between 0 and 20")
        if not 1 <= self.chunk_size <= 64:
            raise ValueError("chunk_size must be between 1 and 64")
        if not 1 <= self.adaptive_batch_samples <= 32:
            raise ValueError("adaptive_batch_samples must be between 1 and 32")
        if not 0 <= self.tail_guard_hops <= 32:
            raise ValueError("tail_guard_hops must be between 0 and 32")
        if not 1 <= self.max_probes <= 100_000:
            raise ValueError("max_probes must be between 1 and 100000")
        if not 1 <= self.destination_port <= 65535:
            raise ValueError("destination_port must be between 1 and 65535")
        if self.source_port is not None and not 1 <= self.source_port <= 65535:
            raise ValueError("source_port must be between 1 and 65535")
        if self.tcp_syn_profile not in {"standard", "minimal"}:
            raise ValueError("tcp_syn_profile must be 'standard' or 'minimal'")
        if self.tcp_connect_control and self.protocol != ProbeProtocol.TCP:
            raise ValueError("tcp_connect_control is available only with --protocol tcp")
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
        required = required_samples(
            self.config.min_detectable_probability, self.config.miss_probability
        )
        regions: List[BoundaryRegion] = []
        tcp_control: Optional[TcpConnectControl] = None
        interrupted = False
        try:
            self._baseline(main_flow)
            analysis_limit = self._analysis_limit(main_flow)
            baseline_answered = self._baseline_answered()
            if baseline_answered:
                self._flow_canaries(main_flow, analysis_limit)
                regions = self._find_regions(analysis_limit)
            if self.config.global_cap and baseline_answered:
                regions = [
                    BoundaryRegion(
                        1,
                        analysis_limit,
                        tuple(range(1, analysis_limit + 1)),
                        ("global CAP coverage requested",),
                        variant_coverage=True,
                        family="global",
                    )
                ]
            self._probe_regions(regions, main_flow, required)
            # Run the optional kernel control only after raw measurement.  A
            # completed connection can create NAT, firewall, proxy, or server
            # state and must not prime the path being diagnosed.
            if (
                self.config.protocol == ProbeProtocol.TCP
                and self.config.tcp_connect_control
            ):
                control_runner = getattr(self.backend, "run_tcp_connect_control", None)
                if control_runner is None:
                    self.warnings.append(
                        "The selected backend does not implement the requested kernel TCP control."
                    )
                else:
                    tcp_control = control_runner(
                        self.config.destination_port, self.config.timeout
                    )
        except KeyboardInterrupt:
            interrupted = True
            self.warnings.append(
                "Measurement interrupted by the user; this is a partial, non-certified result."
            )

        analysis_limit = self._analysis_limit(main_flow)
        baseline_answered = self._baseline_answered()
        if interrupted and baseline_answered and not regions:
            regions = self._find_regions(analysis_limit)
        duration_ms = (time.monotonic_ns() - started) / 1_000_000.0
        terminals = sorted(
            (
                item
                for item in self.observations
                if item.terminal and item.spec.flow == main_flow
            ),
            key=lambda item: (item.spec.ttl, item.sent_ns),
        )
        destination_terminals = [
            item for item in terminals if item.kind == ReplyKind.DESTINATION
        ]
        reached = bool(destination_terminals)
        terminal_observation = terminals[0] if terminals else None
        stop_ttl = terminal_observation.spec.ttl if terminal_observation else None
        probed_max_ttl = max((item.spec.ttl for item in self.observations), default=0)
        has_silent_tail = bool(
            baseline_answered
            and not terminals
            and analysis_limit < probed_max_ttl
        )
        if destination_terminals:
            confirmed = destination_terminals[0]
            if confirmed.responder and confirmed.responder != self.backend.destination:
                self.warnings.append(
                    f"The terminal response came from {confirmed.responder}, not the selected "
                    f"destination address {self.backend.destination}. This can be valid behind "
                    "NAT/load balancing, but it confirms the probed flow rather than endpoint identity."
                )
        if not regions and baseline_answered and not interrupted and not has_silent_tail:
            self.warnings.append(
                "No ambiguous boundary was found; clear hops remain rapid-sweep observations, "
                "not CAP-certified stable edges."
            )
        if baseline_answered and not terminals and not interrupted:
            if self.config.protocol == ProbeProtocol.UDP:
                comparison = "Try --protocol tcp --dport 443 and --protocol icmp"
            elif self.config.protocol == ProbeProtocol.TCP:
                comparison = "Try --protocol icmp and a separate UDP trace"
            else:
                comparison = "Try --protocol tcp --dport 443 and a separate UDP trace"
            self.warnings.append(
                "No terminal response was received. The target may silently filter the "
                "selected traffic class; the last visible responder is not proof that the "
                f"destination was reached. {comparison} as separate diagnostic traces."
            )
            if (
                self.config.protocol == ProbeProtocol.TCP
                and not self.config.tcp_connect_control
            ):
                self.warnings.append(
                    "Use --tcp-connect-control to compare this raw-SYN result with the "
                    "host kernel's TCP stack. The control completes and immediately "
                    "closes a no-application-data handshake; it is never joined to the path."
                )
        if tcp_control is not None:
            if tcp_control.source and tcp_control.source != self.backend.source:
                self.warnings.append(
                    f"Kernel TCP control used source {tcp_control.source}, while raw probes "
                    f"used {self.backend.source}; the control may have followed a different route."
                )
            if tcp_control.positive_transport_response and not reached:
                self.warnings.append(
                    "The kernel TCP control received a positive transport response, but the raw SYN "
                    "trace received no terminal response. This is evidence of probe-shape, "
                    "local-stack/proxy, or policy-dependent visibility—not proof of endpoint unreachability "
                    "and not a recoverable hidden-hop sequence."
                )
            elif not tcp_control.positive_transport_response:
                self.warnings.append(
                    "The kernel TCP control also received no positive transport response; this remains "
                    "compatible with filtering, routing failure, or a nonresponsive service."
                )
        hops = self._summarize_hops(stop_ttl or analysis_limit, main_flow)
        segments = self._summarize_segments(regions, hops, required)
        if has_silent_tail:
            segments.append(self._summarize_silent_tail(analysis_limit, probed_max_ttl, hops))
            segments.sort(key=lambda item: (item.first_ttl, item.last_ttl, item.type.value))
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
                "temporal_samples": self.config.temporal_samples,
                "canary_flows": self.config.canary_flows,
                "global_cap": self.config.global_cap,
                "flow_identity": main_flow.token,
                "destination_port": (
                    main_flow.destination_port
                    if main_flow.protocol in (ProbeProtocol.UDP, ProbeProtocol.TCP)
                    else None
                ),
                "tcp_syn_profile": (
                    self.config.tcp_syn_profile
                    if self.config.protocol == ProbeProtocol.TCP
                    else None
                ),
                "tcp_connect_control": self.config.tcp_connect_control,
            },
            termination=(
                TerminationSummary(
                    ttl=terminal_observation.spec.ttl,
                    kind=terminal_observation.kind,
                    responder=terminal_observation.responder,
                    icmp_type=terminal_observation.icmp_type,
                    icmp_code=terminal_observation.icmp_code,
                    tcp_flags=terminal_observation.tcp_flags,
                )
                if terminal_observation
                else None
            ),
            probed_max_ttl=probed_max_ttl,
            interrupted=interrupted,
            tcp_connect_control=tcp_control,
        )
        self.backend.close()
        return result

    def _baseline_answered(self) -> bool:
        return any(
            item.answered and item.spec.phase == "baseline-fixed"
            for item in self.observations
        )

    def _analysis_limit(self, main_flow: FlowKey) -> int:
        terminal_ttls = [
            item.spec.ttl
            for item in self.observations
            if item.terminal and item.spec.flow == main_flow
        ]
        if terminal_ttls:
            return min(terminal_ttls)
        return self._last_observed_ttl() or self.config.max_hops

    def _main_flow(self) -> FlowKey:
        if self.config.protocol in (ProbeProtocol.UDP, ProbeProtocol.TCP):
            source_port = self.config.source_port or self.random.randrange(49152, 65536)
            return FlowKey(
                protocol=self.config.protocol,
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
        if main.protocol in (ProbeProtocol.UDP, ProbeProtocol.TCP):
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
            if terminal_ttl is not None:
                sweep_limit = terminal_ttl
            elif round_index == 0:
                # The first sweep preserves classic traceroute coverage.  Later
                # repeats need only cover the already visible range plus a small
                # guard; probing the known-silent tail again adds no DBP evidence.
                sweep_limit = self.config.max_hops
            else:
                last_visible = self._last_observed_ttl()
                sweep_limit = min(
                    self.config.max_hops,
                    (last_visible + self.config.tail_guard_hops)
                    if last_visible is not None
                    else self.config.max_hops,
                )
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
                response_kind = (
                    "correlated ICMP/TCP response"
                    if self.config.protocol == ProbeProtocol.TCP
                    else "ICMP response"
                )
                self.warnings.append(
                    f"No {response_kind} was received during the first complete fixed-flow "
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
        mutation_profiles: Dict[int, frozenset] = {}
        for ttl in range(1, limit + 1):
            samples = by_ttl.get(ttl, [])
            responders = {item.responder for item in samples if item.responder}
            reasons = []
            combined = samples + canary_by_ttl.get(ttl, [])
            if combined and any(item.answered for item in combined) and any(
                not item.answered for item in combined
            ):
                reasons.append("intermittent response visibility")
            elif combined and all(not item.answered for item in combined):
                reasons.append("unobservable TTL")
            if len(responders) > 1:
                reasons.append("same-flow responder variation")
            mutation_profiles[ttl] = frozenset(
                mutation for item in samples if item.answered for mutation in item.mutations
            )
            fixed_addresses = {item.responder for item in samples if item.responder}
            canary_addresses = {
                item.responder for item in canary_by_ttl.get(ttl, []) if item.responder
            }
            # A canary choosing one member of an already time-varying fixed
            # set is not evidence of flow sensitivity.  Require a new canary
            # responder, or disagreement with an otherwise stable fixed flow.
            if (
                fixed_addresses
                and canary_addresses
                and (
                    bool(canary_addresses - fixed_addresses)
                    or (len(fixed_addresses) == 1 and fixed_addresses != canary_addresses)
                )
            ):
                reasons.append("flow-sensitive responder")
            fixed_visible = bool(fixed_addresses)
            canary_visible = bool(canary_addresses)
            if samples and canary_by_ttl.get(ttl) and fixed_visible != canary_visible:
                reasons.append("flow-sensitive visibility")
            if reasons:
                suspicious[ttl] = reasons

        # Header rewrites persist downstream.  Repeating "mutation" at every
        # later hop creates a giant false boundary, so mark only the point where
        # the quoted-header profile changes relative to the previous visible TTL.
        previous_profile: frozenset = frozenset()
        for ttl in range(1, limit + 1):
            if not any(item.answered for item in by_ttl.get(ttl, [])):
                continue
            profile = mutation_profiles[ttl]
            if profile != previous_profile:
                suspicious.setdefault(ttl, []).append("quoted-header mutation boundary")
            previous_profile = profile
        if not suspicious:
            return []
        reason_family = {
            # These observations require different claims.  In particular, a
            # persistent silent run can support OPAQUE only when it has visible
            # boundaries, while partial ICMP visibility remains INTERMITTENT.
            "intermittent response visibility": "visibility_intermittent",
            "unobservable TTL": "visibility_silent",
            "flow-sensitive visibility": "visibility_flow",
            "flow-sensitive responder": "multipath",
            "same-flow responder variation": "temporal",
            "quoted-header mutation boundary": "mutation",
        }
        by_family: DefaultDict[str, Dict[int, List[str]]] = defaultdict(dict)
        for ttl, reasons in suspicious.items():
            for reason in reasons:
                family = reason_family[reason]
                by_family[family].setdefault(ttl, []).append(reason)

        regions = []
        for family, family_suspicious in by_family.items():
            groups: List[List[int]] = []
            for ttl in sorted(family_suspicious):
                if not groups or ttl > groups[-1][-1] + 1:
                    groups.append([ttl])
                else:
                    groups[-1].append(ttl)
            for group in groups:
                first = max(1, group[0] - 1)
                last = min(limit, group[-1] + 1)
                if last - first + 1 <= 7:
                    probe_ttls = tuple(range(first, last + 1))
                else:
                    midpoint = (first + last) // 2
                    probe_ttls = tuple(
                        sorted({first, first + 1, midpoint, last - 1, last})
                    )
                reasons = tuple(
                    sorted(
                        {
                            reason
                            for ttl in group
                            for reason in family_suspicious[ttl]
                        }
                    )
                )
                regions.append(
                    BoundaryRegion(
                        first,
                        last,
                        probe_ttls,
                        reasons,
                        variant_coverage=(
                            family.startswith("visibility_") or family == "multipath"
                        ),
                        family=family,
                    )
                )
        return sorted(
            regions,
            key=lambda item: (item.first_ttl, item.last_ttl, item.family),
        )

    def _probe_region(self, region: BoundaryRegion, main_flow: FlowKey, required: int) -> None:
        existing_fixed = self._complete_sample_count(region.probe_ttls, variant=False)
        for _ in range(max(0, self.config.temporal_samples - existing_fixed)):
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
        if not region.variant_coverage:
            return
        existing_varied = self._complete_sample_count(region.probe_ttls, variant=True)
        next_variant = existing_varied + 1
        while next_variant <= required:
            remaining_slots = self.config.max_probes - len(self.observations)
            capacity = remaining_slots // len(region.probe_ttls)
            sample_count = min(
                self.config.adaptive_batch_samples,
                required - next_variant + 1,
                capacity,
            )
            if sample_count <= 0:
                self.warnings.append(
                    "Probe budget exhausted before another complete flow-variant bundle."
                )
                return
            specs = []
            for variant in range(next_variant, next_variant + sample_count):
                sample_id = self._new_sample_id()
                flow = self._variant_flow(variant, main_flow)
                specs.extend(
                    ProbeSpec(
                        ttl=ttl,
                        flow=flow,
                        phase="dbp-varied",
                        sample_id=sample_id,
                        payload_size=self.config.payload_size,
                    )
                    for ttl in region.probe_ttls
                )
            if not self._send(specs):
                return
            next_variant += sample_count

    def _probe_regions(
        self,
        regions: Sequence[BoundaryRegion],
        main_flow: FlowKey,
        required: int,
    ) -> None:
        """Share complete bundles across overlapping cross-flow regions."""

        variant_regions = sorted(
            (item for item in regions if item.variant_coverage),
            key=lambda item: (item.first_ttl, item.last_ttl),
        )
        clusters: List[List[BoundaryRegion]] = []
        for region in variant_regions:
            if (
                not clusters
                or region.first_ttl > max(item.last_ttl for item in clusters[-1])
            ):
                clusters.append([region])
            else:
                clusters[-1].append(region)
        for cluster in clusters:
            probe_ttls = tuple(
                sorted({ttl for item in cluster for ttl in item.probe_ttls})
            )
            aggregate = BoundaryRegion(
                first_ttl=min(item.first_ttl for item in cluster),
                last_ttl=max(item.last_ttl for item in cluster),
                probe_ttls=probe_ttls,
                reasons=("shared adaptive sampling window",),
                variant_coverage=True,
                family="sampling",
            )
            self._probe_region(aggregate, main_flow, required)

        # Fixed-only regions run after shared CAP windows so their temporal
        # sample count can reuse any aggregate sample that covers the same TTLs.
        for region in sorted(
            (item for item in regions if not item.variant_coverage),
            key=lambda item: (item.first_ttl, item.last_ttl),
        ):
            self._probe_region(region, main_flow, required)

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
        special = self._coalesce_segments(
            [self._classify_region(region, hops, required) for region in regions]
        )
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
                    response_rate=min(
                        1.0 - left.loss_rate,
                        1.0 - right.loss_rate,
                    ),
                    certificate=SegmentCertificate(
                        sample_count=samples,
                        min_detectable_probability=self.config.min_detectable_probability,
                        miss_probability_bound=bound,
                        requested_miss_probability=self.config.miss_probability,
                        certified=samples >= required,
                        method="rapid_sweep_observation",
                        required_sample_count=required,
                        assumptions=(
                            "adjacent replies are observations of the fixed flow in the measurement window",
                        ),
                    ),
                    reasons=("adjacent TTL responses from the fixed target flow",),
                )
            )
        return sorted(direct + special, key=lambda item: (item.first_ttl, item.last_ttl))

    @staticmethod
    def _coalesce_segments(segments: Sequence[SegmentSummary]) -> List[SegmentSummary]:
        """Merge duplicate claims while retaining every independent reason.

        Evidence families stay separate during detection and adaptive sampling,
        but two families can converge on the exact same classified behavior.
        Presenting those as duplicate boundaries falsely suggests two path
        events, so they are coalesced only when their evidence summaries and
        certificates are otherwise identical.
        """

        merged: List[SegmentSummary] = []
        for segment in segments:
            duplicate_index = next(
                (
                    index
                    for index, existing in enumerate(merged)
                    if (
                        existing.type == segment.type
                        and existing.first_ttl == segment.first_ttl
                        and existing.last_ttl == segment.last_ttl
                        and existing.ingress == segment.ingress
                        and existing.egress == segment.egress
                        and existing.fixed_outcomes == segment.fixed_outcomes
                        and existing.varied_outcomes == segment.varied_outcomes
                        and existing.certificate == segment.certificate
                        and existing.branches == segment.branches
                    )
                ),
                None,
            )
            if duplicate_index is None:
                merged.append(segment)
                continue
            existing = merged[duplicate_index]
            merged[duplicate_index] = replace(
                existing,
                reasons=tuple(dict.fromkeys(existing.reasons + segment.reasons)),
                explicit_mechanism=(
                    existing.explicit_mechanism or segment.explicit_mechanism
                ),
            )
        return merged

    def _summarize_silent_tail(
        self,
        last_visible_ttl: int,
        probed_max_ttl: int,
        hops: Sequence[HopSummary],
    ) -> SegmentSummary:
        """Represent open-ended silence without inventing an opaque egress.

        A visible ingress followed by timeouts through max TTL is useful
        evidence, but it is observationally compatible with filtering,
        rate-limiting, a protocol policy, or a path longer than the configured
        limit.  It therefore cannot be certified as an OPAQUE segment.
        """

        tail_ttls = tuple(range(last_visible_ttl + 1, probed_max_ttl + 1))
        complete_sweeps = self._complete_sample_count(tail_ttls, variant=False)
        ingress = self._nearest_visible(hops, last_visible_ttl, direction=-1)
        return SegmentSummary(
            type=SegmentType.SILENT_TAIL,
            first_ttl=last_visible_ttl,
            last_ttl=probed_max_ttl,
            ingress=ingress,
            egress=None,
            fixed_outcomes=(),
            varied_outcomes=(),
            empirical_stability=None,
            response_rate=0.0,
            certificate=SegmentCertificate(
                sample_count=complete_sweeps,
                min_detectable_probability=self.config.min_detectable_probability,
                # Fixed-flow silence without an egress has no cross-flow CAP
                # guarantee.  Use the vacuous bound in machine-readable output
                # instead of exposing an easy-to-misread numerical claim.
                miss_probability_bound=1.0,
                requested_miss_probability=self.config.miss_probability,
                certified=False,
                method="silent_tail_observation",
                required_sample_count=self.config.temporal_samples,
                assumptions=(
                    "no response was observed in the complete fixed-flow tail sweep",
                    "there is no visible egress boundary from which to infer internal structure",
                ),
            ),
            reasons=(
                "no response was observed after the last visible TTL through the configured maximum",
                "open-ended silence is not an OPAQUE segment and does not identify a filtering or tunneling mechanism",
            ),
        )

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
        fixed_answered = [item for item in fixed if item.answered]
        fixed_response_rate = len(fixed_answered) / len(fixed) if fixed else None
        fixed_responder_total = 0
        fixed_responder_modal = 0
        for ttl in region.probe_ttls:
            counts = Counter(
                item.responder
                for item in fixed
                if item.spec.ttl == ttl and item.responder is not None
            )
            fixed_responder_total += sum(counts.values())
            fixed_responder_modal += counts.most_common(1)[0][1] if counts else 0
        fixed_stability = (
            fixed_responder_modal / fixed_responder_total
            if fixed_responder_total
            else None
        )
        always_missing = []
        for ttl in region.probe_ttls:
            samples = [item for item in fixed + varied if item.spec.ttl == ttl]
            if samples and all(not item.answered for item in samples):
                always_missing.append(ttl)
        fixed_responder_variation = any(
            len(
                {
                    item.responder
                    for item in fixed
                    if item.spec.ttl == ttl and item.responder is not None
                }
            )
            > 1
            for ttl in region.probe_ttls
        )
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
        branches = []
        for ttl in region.probe_ttls:
            counts = Counter(
                item.responder
                for item in varied
                if item.spec.ttl == ttl and item.responder is not None
            )
            if len(counts) > 1:
                branches.append((ttl, tuple(counts.most_common())))
        mutations = sorted({mutation for item in fixed + varied for mutation in item.mutations})
        fully_answered = bool(fixed and varied) and all(item.answered for item in fixed + varied)
        intermittent_visibility = any(
            any(item.answered for item in fixed + varied if item.spec.ttl == ttl)
            and any(not item.answered for item in fixed + varied if item.spec.ttl == ttl)
            for ttl in region.probe_ttls
        )
        labels = [
            label
            for item in fixed + varied
            if item.extensions
            for label in item.extensions.mpls_labels
        ]

        reasons = list(region.reasons)
        if region.family == "temporal" and fixed_responder_variation:
            segment_type = SegmentType.UNSTABLE
            reasons.append("the same flow produced multiple responder addresses over time")
        elif region.family == "multipath" and varied_responder_multipath:
            segment_type = SegmentType.MULTIPATH
            reasons.append("controlled flow-token variants produced multiple stable signatures")
        elif (
            region.family == "visibility_silent"
            and always_missing
            and self._has_visible_boundaries(region, hops)
        ):
            segment_type = SegmentType.OPAQUE
            reasons.append(
                "one or more sampled TTL positions remained unobservable between visible boundaries"
            )
        elif region.family == "mutation" and mutations:
            segment_type = SegmentType.MUTABLE
            reasons.append("the quoted invoking-packet header profile changes at this boundary")
        elif region.family.startswith("visibility_") and (
            intermittent_visibility or varied_variation or bool(always_missing)
        ):
            segment_type = SegmentType.INTERMITTENT
            reasons.append(
                "ICMP response visibility changed without evidence of a different forwarding responder"
            )
        elif fixed_responder_variation:
            segment_type = SegmentType.UNSTABLE
            reasons.append("the same flow produced multiple responder addresses over time")
        elif varied_responder_multipath:
            segment_type = SegmentType.MULTIPATH
            reasons.append("controlled flow-token variants produced multiple stable signatures")
        elif always_missing and self._has_visible_boundaries(region, hops):
            segment_type = SegmentType.OPAQUE
            reasons.append(
                "one or more sampled TTL positions remained unobservable between visible boundaries"
            )
        elif "quoted-header mutation boundary" in region.reasons and mutations:
            segment_type = SegmentType.MUTABLE
            reasons.append("the quoted invoking-packet header profile changes at this boundary")
        elif intermittent_visibility or varied_variation:
            segment_type = SegmentType.INTERMITTENT
            reasons.append(
                "ICMP response visibility changed without evidence of a different forwarding responder"
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
        fixed_samples = len(fixed_signatures)
        if region.variant_coverage:
            certificate_samples = varied_samples
            certificate_required = required
            certificate_method = "flow_variant_coverage"
            bound = miss_probability_bound(
                self.config.min_detectable_probability, certificate_samples
            )
            certified = (
                fixed_samples >= self.config.temporal_samples
                and certificate_samples >= certificate_required
                and bound <= self.config.miss_probability
            )
            assumptions = (
                "forwarding behavior is stationary during the measurement window",
                "flow variants are uniform samples without replacement from the configured token space",
            )
        else:
            certificate_samples = fixed_samples
            certificate_required = self.config.temporal_samples
            certificate_method = "fixed_flow_repeatability"
            bound = miss_probability_bound(
                self.config.min_detectable_probability, certificate_samples
            )
            certified = certificate_samples >= certificate_required
            assumptions = (
                "repeated observations describe this fixed flow only",
                "the result is evidence of observed behavior, not undiscovered-flow coverage",
            )
        explicit = "MPLS (RFC 4950 label-stack evidence)" if labels else None
        if explicit:
            reasons.append("an ICMP extension explicitly carried an MPLS label stack")
        ingress = self._nearest_visible(hops, region.first_ttl, direction=-1)
        egress = self._nearest_visible(hops, region.last_ttl, direction=1)
        return SegmentSummary(
            type=segment_type,
            first_ttl=region.first_ttl,
            last_ttl=region.last_ttl,
            ingress=ingress,
            egress=egress,
            fixed_outcomes=tuple(fixed_counts.most_common()),
            varied_outcomes=tuple(varied_counts.most_common()),
            empirical_stability=fixed_stability,
            response_rate=fixed_response_rate,
            certificate=SegmentCertificate(
                sample_count=certificate_samples,
                min_detectable_probability=self.config.min_detectable_probability,
                miss_probability_bound=bound,
                requested_miss_probability=self.config.miss_probability,
                certified=certified,
                method=certificate_method,
                required_sample_count=certificate_required,
                assumptions=assumptions,
            ),
            reasons=tuple(dict.fromkeys(reasons)),
            explicit_mechanism=explicit,
            branches=tuple(branches) if segment_type == SegmentType.MULTIPATH else (),
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

    @staticmethod
    def _nearest_visible(
        hops: Sequence[HopSummary], ttl: int, direction: int
    ) -> Optional[str]:
        if not hops:
            return None
        start = min(max(ttl, 1), len(hops))
        indexes = (
            range(start - 1, -1, -1)
            if direction < 0
            else range(start - 1, len(hops))
        )
        for index in indexes:
            if hops[index].primary:
                return hops[index].primary
        return None
