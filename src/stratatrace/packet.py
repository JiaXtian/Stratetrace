"""IPv4 packet construction and defensive ICMP/RFC-extension parsing."""

from __future__ import annotations

import ipaddress
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Optional, Tuple

from .model import ExtensionEvidence, InterfaceInfo, MplsLabel, ReplyKind


TAG_MAGIC = b"STRT"
TAG_FORMAT = "!4sIHBx"
TAG_SIZE = struct.calcsize(TAG_FORMAT)
ICMP_STABLE_CHECKSUM = 0x5A5A


class PacketParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedIPv4:
    header_length: int
    total_length: int
    dscp_ecn: int
    identification: int
    ttl: int
    protocol: int
    source: str
    destination: str
    payload: bytes


@dataclass(frozen=True)
class ParsedResponse:
    probe_id: int
    kind: ReplyKind
    responder: str
    reply_ttl: Optional[int]
    icmp_type: int
    icmp_code: int
    terminal: bool
    quoted_ttl: Optional[int]
    quoted_source: Optional[str]
    quoted_destination: Optional[str]
    quoted_protocol: Optional[int]
    quoted_source_port: Optional[int]
    quoted_destination_port: Optional[int]
    quoted_icmp_identifier: Optional[int]
    quoted_dscp_ecn: Optional[int]
    session_verified: bool
    extensions: Optional[ExtensionEvidence]


def ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def internet_checksum(data: bytes) -> int:
    return (~ones_complement_sum(data)) & 0xFFFF


def _tag(session_id: int, probe_id: int, ttl: int) -> bytes:
    return struct.pack(TAG_FORMAT, TAG_MAGIC, session_id & 0xFFFFFFFF, probe_id & 0xFFFF, ttl)


def _ipv4_header(
    source: str,
    destination: str,
    protocol: int,
    ttl: int,
    identification: int,
    payload_length: int,
    dscp_ecn: int = 0,
) -> bytes:
    if not 1 <= ttl <= 255:
        raise ValueError("ttl must be between 1 and 255")
    total_length = 20 + payload_length
    source_bytes = socket.inet_aton(source)
    destination_bytes = socket.inet_aton(destination)
    without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        dscp_ecn & 0xFF,
        total_length,
        identification & 0xFFFF,
        0,
        ttl,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    checksum = internet_checksum(without_checksum)
    return without_checksum[:10] + struct.pack("!H", checksum) + without_checksum[12:]


def build_udp_probe(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    ttl: int,
    probe_id: int,
    session_id: int,
    payload_size: int = 32,
) -> bytes:
    """Build a flow-consistent IPv4 UDP probe.

    The IPv4 UDP checksum is deliberately zero, which is legal for IPv4 and
    keeps it constant while the payload carries the correlation tag.  The
    five-tuple stays fixed within a FlowKey; IP-ID is the minimum-quote
    fallback correlator.
    """

    if not 1 <= source_port <= 65535 or not 1 <= destination_port <= 65535:
        raise ValueError("UDP ports must be between 1 and 65535")
    tag = _tag(session_id, probe_id, ttl)
    payload = tag + bytes(max(0, payload_size - len(tag)))
    udp_length = 8 + len(payload)
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0) + payload
    return _ipv4_header(
        source,
        destination,
        socket.IPPROTO_UDP,
        ttl,
        probe_id,
        len(udp),
    ) + udp


def _checksum_compensation(data_with_zero_word: bytes, target_checksum: int) -> int:
    current = ones_complement_sum(data_with_zero_word)
    desired = (~target_checksum) & 0xFFFF
    value = (desired - current) % 0xFFFF
    return 0xFFFF if value == 0 else value


def build_icmp_echo_probe(
    source: str,
    destination: str,
    identifier: int,
    ttl: int,
    probe_id: int,
    session_id: int,
    payload_size: int = 32,
) -> bytes:
    """Build ICMP Echo with stable identifier, sequence, and checksum.

    A compensation word keeps the ICMP checksum constant even though the
    payload tag and IPv4 IP-ID identify each probe.
    """

    tag = _tag(session_id, probe_id, ttl)
    body = tag + bytes(max(0, payload_size - len(tag) - 2)) + b"\x00\x00"
    header = struct.pack("!BBHHH", 8, 0, 0, identifier & 0xFFFF, 0)
    compensation = _checksum_compensation(header + body, ICMP_STABLE_CHECKSUM)
    body = body[:-2] + struct.pack("!H", compensation)
    checksum = internet_checksum(header + body)
    if checksum != ICMP_STABLE_CHECKSUM:
        raise AssertionError("failed to construct checksum-neutral ICMP payload")
    icmp = struct.pack(
        "!BBHHH", 8, 0, checksum, identifier & 0xFFFF, 0
    ) + body
    return _ipv4_header(
        source,
        destination,
        socket.IPPROTO_ICMP,
        ttl,
        probe_id,
        len(icmp),
    ) + icmp


def prepare_for_raw_socket(packet: bytes, platform: Optional[str] = None) -> bytes:
    """Translate IP_HDRINCL fields required in host order by BSD kernels.

    Linux accepts ``ip_len`` and ``ip_off`` in network order. Darwin and the
    BSD family document those two fields in host order at the raw socket API;
    the kernel converts them before transmission.
    """

    current = platform or sys.platform
    if current != "darwin" and "bsd" not in current:
        return packet
    if len(packet) < 20:
        raise ValueError("truncated IPv4 packet")
    result = bytearray(packet)
    total_length = struct.unpack_from("!H", result, 2)[0]
    fragment_offset = struct.unpack_from("!H", result, 6)[0]
    struct.pack_into("=H", result, 2, total_length)
    struct.pack_into("=H", result, 6, fragment_offset)
    return bytes(result)


def parse_ipv4(data: bytes) -> ParsedIPv4:
    if len(data) < 20:
        raise PacketParseError("truncated IPv4 header")
    version = data[0] >> 4
    ihl = (data[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        raise PacketParseError("invalid IPv4 header")
    total_length = struct.unpack_from("!H", data, 2)[0]
    if total_length < ihl:
        raise PacketParseError("invalid IPv4 total length")
    available = min(len(data), total_length) if total_length else len(data)
    identification = struct.unpack_from("!H", data, 4)[0]
    return ParsedIPv4(
        header_length=ihl,
        total_length=total_length,
        dscp_ecn=data[1],
        identification=identification,
        ttl=data[8],
        protocol=data[9],
        source=socket.inet_ntoa(data[12:16]),
        destination=socket.inet_ntoa(data[16:20]),
        payload=data[ihl:available],
    )


def _read_tag(data: bytes, offset: int, expected_session: int) -> Tuple[Optional[int], bool]:
    if len(data) < offset + TAG_SIZE:
        return None, False
    magic, session_id, probe_id, _ttl = struct.unpack_from(TAG_FORMAT, data, offset)
    if magic != TAG_MAGIC:
        return None, False
    return probe_id, session_id == (expected_session & 0xFFFFFFFF)


def parse_icmp_response(
    packet: bytes,
    expected_session: int,
    responder_hint: Optional[str] = None,
) -> ParsedResponse:
    """Parse one raw-socket ICMPv4 packet.

    Unknown and malformed extension objects are rejected or retained as
    unknown evidence; they never affect probe correlation.
    """

    outer: Optional[ParsedIPv4]
    if packet and packet[0] >> 4 == 4:
        outer = parse_ipv4(packet)
        if outer.protocol != socket.IPPROTO_ICMP:
            raise PacketParseError("not an ICMPv4 packet")
        icmp = outer.payload
        responder = outer.source
        reply_ttl = outer.ttl
    else:
        outer = None
        icmp = packet
        responder = responder_hint or "0.0.0.0"
        reply_ttl = None
    if len(icmp) < 8:
        raise PacketParseError("truncated ICMP header")
    icmp_type, icmp_code = struct.unpack_from("!BB", icmp, 0)

    if icmp_type == 0:  # Echo Reply
        probe_id, verified = _read_tag(icmp, 8, expected_session)
        if probe_id is None or not verified:
            raise PacketParseError("unrelated ICMP echo reply")
        return ParsedResponse(
            probe_id=probe_id,
            kind=ReplyKind.DESTINATION,
            responder=responder,
            reply_ttl=reply_ttl,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            terminal=True,
            quoted_ttl=None,
            quoted_source=None,
            quoted_destination=None,
            quoted_protocol=None,
            quoted_source_port=None,
            quoted_destination_port=None,
            quoted_icmp_identifier=None,
            quoted_dscp_ecn=None,
            session_verified=True,
            extensions=None,
        )

    if icmp_type not in (3, 11, 12):
        raise PacketParseError("unrelated ICMP message type")
    inner = parse_ipv4(icmp[8:])
    probe_id = inner.identification
    source_port = destination_port = icmp_identifier = None
    session_verified = False
    tag_probe_id: Optional[int] = None
    if inner.protocol == socket.IPPROTO_UDP and len(inner.payload) >= 8:
        source_port, destination_port = struct.unpack_from("!HH", inner.payload, 0)
        tag_probe_id, session_verified = _read_tag(inner.payload, 8, expected_session)
    elif inner.protocol == socket.IPPROTO_ICMP and len(inner.payload) >= 8:
        _inner_type, _inner_code, _sum, icmp_identifier, _seq = struct.unpack_from(
            "!BBHHH", inner.payload, 0
        )
        tag_probe_id, session_verified = _read_tag(inner.payload, 8, expected_session)
    if tag_probe_id is not None:
        if not session_verified:
            raise PacketParseError("probe tag belongs to a different session")
        probe_id = tag_probe_id

    extensions = parse_icmp_extensions(icmp)
    if icmp_type == 11:
        kind = ReplyKind.TIME_EXCEEDED
        terminal = False
    elif icmp_type == 3 and icmp_code == 3 and inner.protocol == socket.IPPROTO_UDP:
        kind = ReplyKind.DESTINATION
        terminal = True
    else:
        kind = ReplyKind.UNREACHABLE if icmp_type == 3 else ReplyKind.OTHER
        terminal = icmp_type == 3

    return ParsedResponse(
        probe_id=probe_id,
        kind=kind,
        responder=responder,
        reply_ttl=reply_ttl,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        terminal=terminal,
        quoted_ttl=inner.ttl,
        quoted_source=inner.source,
        quoted_destination=inner.destination,
        quoted_protocol=inner.protocol,
        quoted_source_port=source_port,
        quoted_destination_port=destination_port,
        quoted_icmp_identifier=icmp_identifier,
        quoted_dscp_ecn=inner.dscp_ecn,
        session_verified=session_verified,
        extensions=extensions,
    )


def _looks_like_extension(data: bytes) -> bool:
    return len(data) >= 4 and data[0] >> 4 == 2


def parse_icmp_extensions(icmp: bytes) -> Optional[ExtensionEvidence]:
    if len(icmp) < 12 or icmp[0] not in (3, 11, 12):
        return None
    quoted_words = icmp[5]
    extension_offset: Optional[int] = None
    if quoted_words:
        candidate = 8 + quoted_words * 4
        if candidate <= len(icmp) - 4 and _looks_like_extension(icmp[candidate:]):
            extension_offset = candidate
    elif len(icmp) >= 8 + 128 + 4:
        candidate = 8 + 128
        if _looks_like_extension(icmp[candidate:]):
            extension_offset = candidate
    if extension_offset is None:
        return None

    extension = icmp[extension_offset:]
    transmitted_checksum = struct.unpack_from("!H", extension, 2)[0]
    valid_checksum = transmitted_checksum == 0 or internet_checksum(extension) == 0
    if not valid_checksum:
        return ExtensionEvidence(valid_checksum=False)

    mpls = []
    interfaces = []
    unknown = []
    offset = 4
    while offset + 4 <= len(extension):
        length, class_number, ctype = struct.unpack_from("!HBB", extension, offset)
        if length < 4 or length % 4 or offset + length > len(extension):
            break
        payload = extension[offset + 4 : offset + length]
        if class_number == 1 and ctype == 1:
            for label_offset in range(0, len(payload) - 3, 4):
                entry = struct.unpack_from("!I", payload, label_offset)[0]
                mpls.append(
                    MplsLabel(
                        label=(entry >> 12) & 0xFFFFF,
                        traffic_class=(entry >> 9) & 0x7,
                        bottom_of_stack=bool((entry >> 8) & 0x1),
                        ttl=entry & 0xFF,
                    )
                )
        elif class_number == 2:
            parsed = _parse_interface_info(ctype, payload)
            if parsed is not None:
                interfaces.append(parsed)
        else:
            unknown.append((class_number, ctype, length))
        offset += length
    return ExtensionEvidence(
        valid_checksum=True,
        mpls_labels=tuple(mpls),
        interfaces=tuple(interfaces),
        unknown_objects=tuple(unknown),
    )


def _parse_interface_info(ctype: int, payload: bytes) -> Optional[InterfaceInfo]:
    roles = ("incoming", "sub-ip incoming", "outgoing", "next-hop")
    role = roles[(ctype >> 6) & 0x03]
    has_ifindex = bool(ctype & 0x08)
    has_address = bool(ctype & 0x04)
    has_name = bool(ctype & 0x02)
    has_mtu = bool(ctype & 0x01)
    offset = 0
    ifindex = None
    address = None
    name = None
    mtu = None
    try:
        if has_ifindex:
            ifindex = struct.unpack_from("!I", payload, offset)[0]
            offset += 4
        if has_address:
            afi = struct.unpack_from("!H", payload, offset)[0]
            offset += 4  # AFI and reserved
            if afi == 1:
                address = str(ipaddress.IPv4Address(payload[offset : offset + 4]))
                offset += 4
            elif afi == 2:
                address = str(ipaddress.IPv6Address(payload[offset : offset + 16]))
                offset += 16
            else:
                return None
        if has_name:
            name_length = payload[offset]
            if name_length < 1 or name_length > 64:
                return None
            name = payload[offset + 1 : offset + name_length].decode("utf-8", "replace")
            offset += (name_length + 3) & ~3
        if has_mtu:
            mtu = struct.unpack_from("!I", payload, offset)[0]
    except (IndexError, struct.error, ipaddress.AddressValueError):
        return None
    return InterfaceInfo(role=role, ifindex=ifindex, address=address, name=name, mtu=mtu)
