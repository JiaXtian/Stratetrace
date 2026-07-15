"""Typed data model shared by probing, analysis, and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ProbeProtocol(str, Enum):
    UDP = "udp"
    ICMP = "icmp"


class ReplyKind(str, Enum):
    TIME_EXCEEDED = "time_exceeded"
    DESTINATION = "destination"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    OTHER = "other"


class SegmentType(str, Enum):
    DIRECT = "direct"
    MULTIPATH = "multipath"
    OPAQUE = "opaque"
    MUTABLE = "mutable"
    INTERMITTENT = "intermittent"
    UNSTABLE = "unstable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FlowKey:
    """Fields intentionally kept equal for one forwarding-equivalence sample."""

    protocol: ProbeProtocol
    source_port: int = 0
    destination_port: int = 0
    icmp_identifier: int = 0
    variant: int = 0

    @property
    def token(self) -> str:
        if self.protocol == ProbeProtocol.UDP:
            return f"udp:{self.source_port}:{self.destination_port}:v{self.variant}"
        return f"icmp:{self.icmp_identifier}:v{self.variant}"


@dataclass(frozen=True)
class ProbeSpec:
    ttl: int
    flow: FlowKey
    phase: str
    sample_id: int
    probe_id: int = 0
    payload_size: int = 32


@dataclass(frozen=True)
class MplsLabel:
    label: int
    traffic_class: int
    bottom_of_stack: bool
    ttl: int


@dataclass(frozen=True)
class InterfaceInfo:
    role: str
    ifindex: Optional[int] = None
    address: Optional[str] = None
    name: Optional[str] = None
    mtu: Optional[int] = None


@dataclass(frozen=True)
class ExtensionEvidence:
    valid_checksum: bool
    mpls_labels: Tuple[MplsLabel, ...] = ()
    interfaces: Tuple[InterfaceInfo, ...] = ()
    unknown_objects: Tuple[Tuple[int, int, int], ...] = ()


@dataclass
class ProbeObservation:
    spec: ProbeSpec
    kind: ReplyKind
    responder: Optional[str]
    rtt_ms: Optional[float]
    sent_ns: int
    received_ns: Optional[int] = None
    reply_ttl: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    quoted_ttl: Optional[int] = None
    terminal: bool = False
    extensions: Optional[ExtensionEvidence] = None
    mutations: Tuple[str, ...] = ()
    matched_by: str = "ip_id"

    @property
    def answered(self) -> bool:
        return self.responder is not None and self.kind != ReplyKind.TIMEOUT


@dataclass(frozen=True)
class HopSummary:
    ttl: int
    primary: Optional[str]
    responders: Tuple[Tuple[str, int], ...]
    sent: int
    answered: int
    loss_rate: float
    rtt_min_ms: Optional[float]
    rtt_median_ms: Optional[float]
    rtt_max_ms: Optional[float]
    mpls_labels: Tuple[MplsLabel, ...] = ()
    interfaces: Tuple[InterfaceInfo, ...] = ()
    mutations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class BoundaryRegion:
    first_ttl: int
    last_ttl: int
    probe_ttls: Tuple[int, ...]
    reasons: Tuple[str, ...]
    variant_coverage: bool = False


@dataclass(frozen=True)
class SegmentCertificate:
    """A detection-coverage certificate, not a probability of topology truth."""

    sample_count: int
    min_detectable_probability: float
    miss_probability_bound: float
    requested_miss_probability: float
    certified: bool
    method: str = "flow_variant_coverage"
    required_sample_count: int = 0
    assumptions: Tuple[str, ...] = (
        "forwarding behavior is stationary during the measurement window",
        "flow variants are uniform samples without replacement from the configured token space",
    )


@dataclass(frozen=True)
class SegmentSummary:
    type: SegmentType
    first_ttl: int
    last_ttl: int
    ingress: Optional[str]
    egress: Optional[str]
    fixed_outcomes: Tuple[Tuple[str, int], ...]
    varied_outcomes: Tuple[Tuple[str, int], ...]
    empirical_stability: Optional[float]
    response_rate: Optional[float]
    certificate: SegmentCertificate
    reasons: Tuple[str, ...]
    explicit_mechanism: Optional[str] = None


@dataclass
class TraceResult:
    target: str
    destination: str
    source: str
    protocol: ProbeProtocol
    started_at: str
    duration_ms: float
    reached: bool
    terminal_ttl: Optional[int]
    probe_count: int
    baseline_probe_count: int
    adaptive_probe_count: int
    hops: List[HopSummary] = field(default_factory=list)
    segments: List[SegmentSummary] = field(default_factory=list)
    observations: List[ProbeObservation] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    policy: Dict[str, Any] = field(default_factory=dict)
    termination: Optional["TerminationSummary"] = None
    probed_max_ttl: int = 0
    interrupted: bool = False

    def to_dict(self, include_observations: bool = True) -> Dict[str, Any]:
        raw = asdict(self)
        raw["protocol"] = self.protocol.value
        if not include_observations:
            raw.pop("observations", None)
        return _enum_values(raw)


@dataclass(frozen=True)
class TerminationSummary:
    ttl: int
    kind: ReplyKind
    responder: Optional[str]
    icmp_type: Optional[int]
    icmp_code: Optional[int]


def _enum_values(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _enum_values(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_enum_values(item) for item in value]
    return value
