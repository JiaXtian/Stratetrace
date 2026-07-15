import socket
import struct
import unittest

from stratatrace.model import ReplyKind
from stratatrace.packet import (
    ICMP_STABLE_CHECKSUM,
    _ipv4_header,
    build_icmp_echo_probe,
    build_udp_probe,
    internet_checksum,
    parse_icmp_response,
    parse_ipv4,
    prepare_for_raw_socket,
)


SOURCE = "192.0.2.10"
TARGET = "203.0.113.9"
ROUTER = "198.51.100.1"
SESSION = 0x12345678


def extension_bytes(corrupt=False):
    lse = (16003 << 12) | (1 << 8) | 7
    mpls_object = struct.pack("!HBBI", 8, 1, 1, lse)
    interface_payload = (
        struct.pack("!I", 17)
        + struct.pack("!HH", 1, 0)
        + socket.inet_aton("198.51.100.7")
        + struct.pack("!I", 1500)
    )
    interface_object = struct.pack("!HBB", 4 + len(interface_payload), 2, 0x0D) + interface_payload
    extension = b"\x20\x00\x00\x00" + mpls_object + interface_object
    checksum = internet_checksum(extension)
    extension = extension[:2] + struct.pack("!H", checksum) + extension[4:]
    if corrupt:
        extension = extension[:-1] + bytes([extension[-1] ^ 0xFF])
    return extension


def icmp_error(original, icmp_type=11, code=0, extensions=b""):
    if extensions:
        quoted = original + bytes(128 - len(original))
        length_words = 32
    else:
        quoted = original[:28]
        length_words = 0
    header = struct.pack("!BBHBBH", icmp_type, code, 0, 0, length_words, 0)
    body = header + quoted + extensions
    body = body[:2] + struct.pack("!H", internet_checksum(body)) + body[4:]
    return _ipv4_header(ROUTER, SOURCE, socket.IPPROTO_ICMP, 57, 99, len(body)) + body


class PacketTests(unittest.TestCase):
    def test_udp_probe_is_valid_and_flow_fields_are_fixed(self):
        first = build_udp_probe(SOURCE, TARGET, 53000, 33434, 3, 10, SESSION)
        second = build_udp_probe(SOURCE, TARGET, 53000, 33434, 4, 11, SESSION)
        first_ip = parse_ipv4(first)
        second_ip = parse_ipv4(second)
        self.assertEqual(first_ip.protocol, socket.IPPROTO_UDP)
        self.assertEqual(struct.unpack_from("!HH", first_ip.payload), (53000, 33434))
        self.assertEqual(struct.unpack_from("!H", first_ip.payload, 6)[0], 0)
        self.assertEqual(first_ip.payload[:8], second_ip.payload[:8])

    def test_icmp_probe_uses_stable_checksum(self):
        first = parse_ipv4(build_icmp_echo_probe(SOURCE, TARGET, 42, 2, 4, SESSION))
        second = parse_ipv4(build_icmp_echo_probe(SOURCE, TARGET, 42, 3, 5, SESSION))
        self.assertEqual(internet_checksum(first.payload), 0)
        self.assertEqual(internet_checksum(second.payload), 0)
        self.assertEqual(struct.unpack_from("!H", first.payload, 2)[0], ICMP_STABLE_CHECKSUM)
        self.assertEqual(struct.unpack_from("!H", second.payload, 2)[0], ICMP_STABLE_CHECKSUM)

    def test_rfc_extensions_are_parsed(self):
        original = build_udp_probe(SOURCE, TARGET, 53000, 33434, 3, 77, SESSION)
        parsed = parse_icmp_response(icmp_error(original, extensions=extension_bytes()), SESSION)
        self.assertEqual(parsed.probe_id, 77)
        self.assertTrue(parsed.session_verified)
        self.assertEqual(parsed.kind, ReplyKind.TIME_EXCEEDED)
        self.assertTrue(parsed.extensions.valid_checksum)
        self.assertEqual(parsed.extensions.mpls_labels[0].label, 16003)
        self.assertEqual(parsed.extensions.mpls_labels[0].ttl, 7)
        interface = parsed.extensions.interfaces[0]
        self.assertEqual(interface.ifindex, 17)
        self.assertEqual(interface.address, "198.51.100.7")
        self.assertEqual(interface.mtu, 1500)

    def test_bad_extension_checksum_is_not_trusted(self):
        original = build_udp_probe(SOURCE, TARGET, 53000, 33434, 3, 78, SESSION)
        parsed = parse_icmp_response(
            icmp_error(original, extensions=extension_bytes(corrupt=True)), SESSION
        )
        self.assertFalse(parsed.extensions.valid_checksum)
        self.assertFalse(parsed.extensions.mpls_labels)

    def test_minimum_quote_falls_back_to_ip_id_and_flow(self):
        original = build_udp_probe(SOURCE, TARGET, 53000, 33434, 5, 79, SESSION)
        parsed = parse_icmp_response(icmp_error(original), SESSION)
        self.assertEqual(parsed.probe_id, 79)
        self.assertFalse(parsed.session_verified)
        self.assertEqual(parsed.quoted_source_port, 53000)
        self.assertEqual(parsed.quoted_destination_port, 33434)

    def test_udp_port_unreachable_marks_destination(self):
        original = build_udp_probe(SOURCE, TARGET, 53000, 33434, 5, 80, SESSION)
        parsed = parse_icmp_response(icmp_error(original, icmp_type=3, code=3), SESSION)
        self.assertEqual(parsed.kind, ReplyKind.DESTINATION)
        self.assertTrue(parsed.terminal)

    def test_darwin_raw_socket_uses_host_order_length_fields(self):
        packet = build_udp_probe(SOURCE, TARGET, 53000, 33434, 5, 81, SESSION)
        prepared = prepare_for_raw_socket(packet, platform="darwin")
        self.assertEqual(struct.unpack_from("=H", prepared, 2)[0], len(packet))
        self.assertEqual(struct.unpack_from("=H", prepared, 6)[0], 0)
        self.assertEqual(prepare_for_raw_socket(packet, platform="linux"), packet)


if __name__ == "__main__":
    unittest.main()
