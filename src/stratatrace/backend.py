"""Real raw-socket and deterministic scripted probe backends."""

from __future__ import annotations

import json
import ipaddress
import random
import select
import socket
import time
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Sequence, Tuple

from .model import (
    ExtensionEvidence,
    FlowKey,
    InterfaceInfo,
    MplsLabel,
    ProbeObservation,
    ProbeProtocol,
    ProbeSpec,
    ReplyKind,
)
from .packet import (
    PacketParseError,
    build_icmp_echo_probe,
    build_udp_probe,
    parse_icmp_response,
    prepare_for_raw_socket,
)


class BackendError(RuntimeError):
    pass


class PrivilegeError(BackendError):
    pass


BENCHMARK_NETWORK = ipaddress.IPv4Network("198.18.0.0/15")


def benchmark_address_diagnostic(destination: str, source: str) -> Optional[str]:
    """Explain RFC 2544 addresses commonly used by fake-IP/TUN proxies."""

    affected = []
    for role, address in (("destination", destination), ("source", source)):
        try:
            if ipaddress.IPv4Address(address) in BENCHMARK_NETWORK:
                affected.append(f"{role}={address}")
        except ipaddress.AddressValueError:
            continue
    if not affected:
        return None
    return (
        f"{', '.join(affected)} is inside 198.18.0.0/15, the RFC 2544 "
        "benchmarking range. For public hostnames this usually means a VPN/proxy "
        "fake-IP TUN is active; raw TTL probes only see the synthetic mapping and "
        "cannot measure the original Internet path. Disable fake-IP/TUN routing "
        "for the measurement, or use --allow-benchmark-address only for an "
        "intentional isolated benchmark lab."
    )


class ProbeBackend(Protocol):
    source: str
    destination: str
    session_id: int
    probe_count: int

    def send_batch(self, specs: Sequence[ProbeSpec]) -> List[ProbeObservation]:
        ...

    def close(self) -> None:
        ...


def discover_ipv4_source(destination: str) -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((destination, 9))
        return str(probe.getsockname()[0])
    except OSError as exc:
        raise BackendError(f"cannot select an IPv4 source route to {destination}: {exc}") from exc
    finally:
        probe.close()


class RawIPv4Backend:
    """Craft and correlate raw IPv4 probes.

    Raw sockets normally require root or CAP_NET_RAW.  StrataTrace fails
    closed when that authority is unavailable; it never silently falls back
    to a flow-inconsistent system traceroute.
    """

    def __init__(
        self,
        destination: str,
        source: Optional[str] = None,
        timeout: float = 1.0,
        pacing_ms: float = 1.0,
        session_id: Optional[int] = None,
        allow_benchmark_address: bool = False,
    ) -> None:
        self.destination = destination
        destination_diagnostic = benchmark_address_diagnostic(self.destination, "0.0.0.0")
        if destination_diagnostic and not allow_benchmark_address:
            raise BackendError(destination_diagnostic)
        self.source = source or discover_ipv4_source(destination)
        diagnostic = benchmark_address_diagnostic(self.destination, self.source)
        if diagnostic and not allow_benchmark_address:
            raise BackendError(diagnostic)
        self.timeout = timeout
        self.pacing_seconds = pacing_ms / 1000.0
        self.session_id = session_id if session_id is not None else random.SystemRandom().getrandbits(32)
        self.probe_count = 0
        self._next_probe_id = random.SystemRandom().randrange(1, 65535)
        try:
            self._send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self._send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._receive = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self._receive.setblocking(False)
        except PermissionError as exc:
            self.close()
            raise PrivilegeError(
                "raw IPv4 sockets are unavailable; run as root or grant CAP_NET_RAW "
                "to the Python executable (Linux). Use --simulate to validate without privileges."
            ) from exc
        except OSError as exc:
            self.close()
            raise BackendError(f"cannot initialize raw IPv4 sockets: {exc}") from exc

    def close(self) -> None:
        for name in ("_send", "_receive"):
            sock = getattr(self, name, None)
            if sock is not None:
                try:
                    sock.close()
                finally:
                    setattr(self, name, None)

    def __enter__(self) -> "RawIPv4Backend":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _allocate_probe_id(self) -> int:
        result = self._next_probe_id
        self._next_probe_id = 1 if result == 65535 else result + 1
        return result

    def _packet(self, spec: ProbeSpec) -> bytes:
        if spec.flow.protocol == ProbeProtocol.UDP:
            return build_udp_probe(
                self.source,
                self.destination,
                spec.flow.source_port,
                spec.flow.destination_port,
                spec.ttl,
                spec.probe_id,
                self.session_id,
                spec.payload_size,
            )
        return build_icmp_echo_probe(
            self.source,
            self.destination,
            spec.flow.icmp_identifier,
            spec.ttl,
            spec.probe_id,
            self.session_id,
            spec.payload_size,
        )

    def send_batch(self, specs: Sequence[ProbeSpec]) -> List[ProbeObservation]:
        if not specs:
            return []
        outstanding: Dict[int, Tuple[ProbeSpec, int]] = {}
        observations: Dict[int, ProbeObservation] = {}
        for index, requested in enumerate(specs):
            spec = replace(requested, probe_id=self._allocate_probe_id())
            packet = prepare_for_raw_socket(self._packet(spec))
            sent_ns = time.monotonic_ns()
            try:
                self._send.sendto(packet, (self.destination, 0))
            except OSError as exc:
                raise BackendError(f"failed to send TTL {spec.ttl} probe: {exc}") from exc
            outstanding[spec.probe_id] = (spec, sent_ns)
            self.probe_count += 1
            if self.pacing_seconds and index + 1 < len(specs):
                time.sleep(self.pacing_seconds)

        deadline = time.monotonic() + self.timeout
        while len(observations) < len(outstanding):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([self._receive], [], [], remaining)
            if not readable:
                break
            try:
                packet, address = self._receive.recvfrom(65535)
                parsed = parse_icmp_response(packet, self.session_id, str(address[0]))
            except (BlockingIOError, PacketParseError):
                continue
            pending = outstanding.get(parsed.probe_id)
            if pending is None or parsed.probe_id in observations:
                continue
            spec, sent_ns = pending
            if not self._matches_flow(parsed, spec.flow):
                continue
            received_ns = time.monotonic_ns()
            mutations = self._mutations(parsed, spec.flow)
            observations[parsed.probe_id] = ProbeObservation(
                spec=spec,
                kind=parsed.kind,
                responder=parsed.responder,
                rtt_ms=(received_ns - sent_ns) / 1_000_000.0,
                sent_ns=sent_ns,
                received_ns=received_ns,
                reply_ttl=parsed.reply_ttl,
                icmp_type=parsed.icmp_type,
                icmp_code=parsed.icmp_code,
                quoted_ttl=parsed.quoted_ttl,
                terminal=parsed.terminal,
                extensions=parsed.extensions,
                mutations=mutations,
                matched_by="payload_tag" if parsed.session_verified else "ip_id+flow",
            )

        result = []
        for probe_id, (spec, sent_ns) in outstanding.items():
            result.append(
                observations.get(
                    probe_id,
                    ProbeObservation(
                        spec=spec,
                        kind=ReplyKind.TIMEOUT,
                        responder=None,
                        rtt_ms=None,
                        sent_ns=sent_ns,
                    ),
                )
            )
        return result

    def _matches_flow(self, parsed: object, flow: FlowKey) -> bool:
        protocol = getattr(parsed, "quoted_protocol")
        if protocol is None:  # direct Echo Reply
            return flow.protocol == ProbeProtocol.ICMP
        expected_protocol = socket.IPPROTO_UDP if flow.protocol == ProbeProtocol.UDP else socket.IPPROTO_ICMP
        if protocol != expected_protocol:
            return False
        if getattr(parsed, "session_verified"):
            # A full session tag is a stronger correlator than quoted fields,
            # so translated fields remain usable mutation evidence.
            return True
        if getattr(parsed, "quoted_destination") != self.destination:
            return False
        if flow.protocol == ProbeProtocol.UDP:
            # Permit source-port mutation so it can be reported, but require
            # the destination port to reject unrelated same-IP-ID traffic.
            return getattr(parsed, "quoted_destination_port") == flow.destination_port
        identifier = getattr(parsed, "quoted_icmp_identifier")
        return identifier is None or identifier == flow.icmp_identifier

    def _mutations(self, parsed: object, flow: FlowKey) -> Tuple[str, ...]:
        mutations = []
        quoted_source = getattr(parsed, "quoted_source")
        if quoted_source is not None and quoted_source != self.source:
            mutations.append(f"source-address:{self.source}->{quoted_source}")
        quoted_destination = getattr(parsed, "quoted_destination")
        if quoted_destination is not None and quoted_destination != self.destination:
            mutations.append(f"destination-address:{self.destination}->{quoted_destination}")
        quoted_dscp_ecn = getattr(parsed, "quoted_dscp_ecn")
        if quoted_dscp_ecn is not None:
            quoted_dscp = quoted_dscp_ecn >> 2
            quoted_ecn = quoted_dscp_ecn & 0x03
            if quoted_dscp:
                mutations.append(f"dscp:0->{quoted_dscp}")
            if quoted_ecn:
                mutations.append(f"ecn:0->{quoted_ecn}")
        if flow.protocol == ProbeProtocol.UDP:
            quoted_source_port = getattr(parsed, "quoted_source_port")
            if quoted_source_port is not None and quoted_source_port != flow.source_port:
                mutations.append(f"source-port:{flow.source_port}->{quoted_source_port}")
            quoted_destination_port = getattr(parsed, "quoted_destination_port")
            if (
                quoted_destination_port is not None
                and quoted_destination_port != flow.destination_port
            ):
                mutations.append(
                    f"destination-port:{flow.destination_port}->{quoted_destination_port}"
                )
        else:
            quoted_identifier = getattr(parsed, "quoted_icmp_identifier")
            if quoted_identifier is not None and quoted_identifier != flow.icmp_identifier:
                mutations.append(f"icmp-identifier:{flow.icmp_identifier}->{quoted_identifier}")
        return tuple(mutations)


class ScriptedBackend:
    """Deterministic backend for algorithm tests and reproducible demos."""

    def __init__(self, fixture: Path) -> None:
        with fixture.open("r", encoding="utf-8") as handle:
            self.scenario = json.load(handle)
        self.destination = str(self.scenario.get("destination", "203.0.113.254"))
        self.source = str(self.scenario.get("source", "192.0.2.10"))
        self.session_id = int(self.scenario.get("session_id", 1))
        self.probe_count = 0
        self._next_probe_id = 1
        self._fixed_calls: Dict[int, int] = {}

    def close(self) -> None:
        return None

    def send_batch(self, specs: Sequence[ProbeSpec]) -> List[ProbeObservation]:
        result = []
        now = time.monotonic_ns()
        hops = self.scenario.get("hops", {})
        for requested in specs:
            spec = replace(requested, probe_id=self._next_probe_id)
            self._next_probe_id += 1
            self.probe_count += 1
            rule = hops.get(str(spec.ttl), {})
            outcomes = rule.get("varied" if spec.flow.variant else "fixed", rule.get("fixed", [None]))
            if not isinstance(outcomes, list) or not outcomes:
                outcomes = [None]
            if spec.flow.variant:
                outcome = outcomes[(spec.flow.variant - 1) % len(outcomes)]
            else:
                call = self._fixed_calls.get(spec.ttl, 0)
                outcome = outcomes[call % len(outcomes)]
                self._fixed_calls[spec.ttl] = call + 1
            responder = str(outcome) if outcome is not None else None
            terminal = bool(rule.get("terminal", False) and responder)
            terminal_kind = ReplyKind(str(rule.get("terminal_kind", "destination")))
            rtt_ms = float(rule.get("rtt_ms", spec.ttl)) if responder else None
            extensions = self._extensions(rule)
            mutations = tuple(str(item) for item in rule.get("mutations", []))
            result.append(
                ProbeObservation(
                    spec=spec,
                    kind=(
                        terminal_kind
                        if terminal
                        else ReplyKind.TIME_EXCEEDED
                        if responder
                        else ReplyKind.TIMEOUT
                    ),
                    responder=responder,
                    rtt_ms=rtt_ms,
                    sent_ns=now,
                    received_ns=now + int(rtt_ms * 1_000_000) if rtt_ms is not None else None,
                    reply_ttl=58 if responder else None,
                    icmp_type=3 if terminal else 11 if responder else None,
                    icmp_code=(
                        13
                        if terminal and terminal_kind == ReplyKind.UNREACHABLE
                        else 3
                        if terminal
                        else 0
                        if responder
                        else None
                    ),
                    quoted_ttl=0 if responder else None,
                    terminal=terminal,
                    extensions=extensions,
                    mutations=mutations,
                    matched_by="simulation",
                )
            )
        return result

    @staticmethod
    def _extensions(rule: Dict[str, object]) -> Optional[ExtensionEvidence]:
        labels = []
        for item in rule.get("mpls", []):  # type: ignore[union-attr]
            labels.append(
                MplsLabel(
                    label=int(item["label"]),
                    traffic_class=int(item.get("traffic_class", 0)),
                    bottom_of_stack=bool(item.get("bottom_of_stack", True)),
                    ttl=int(item.get("ttl", 1)),
                )
            )
        interfaces = []
        for item in rule.get("interfaces", []):  # type: ignore[union-attr]
            interfaces.append(
                InterfaceInfo(
                    role=str(item.get("role", "incoming")),
                    ifindex=item.get("ifindex"),
                    address=item.get("address"),
                    name=item.get("name"),
                    mtu=item.get("mtu"),
                )
            )
        if not labels and not interfaces:
            return None
        return ExtensionEvidence(True, tuple(labels), tuple(interfaces))
