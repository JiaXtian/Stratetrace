import socket
import errno
import unittest
from types import SimpleNamespace
from unittest import mock

from stratatrace.backend import RawIPv4Backend, benchmark_address_diagnostic
from stratatrace.model import FlowKey, ProbeProtocol, TcpControlStatus


class BackendEvidenceTests(unittest.TestCase):
    def setUp(self):
        # Avoid opening raw sockets: these methods only consume parsed data.
        self.backend = object.__new__(RawIPv4Backend)
        self.backend.source = "192.0.2.10"
        self.backend.destination = "203.0.113.9"
        self.flow = FlowKey(ProbeProtocol.UDP, 53000, 33434)

    def test_verified_tag_allows_translated_flow_to_be_correlated(self):
        parsed = SimpleNamespace(
            quoted_protocol=socket.IPPROTO_UDP,
            quoted_destination="198.51.100.9",
            quoted_destination_port=443,
            session_verified=True,
        )
        self.assertTrue(self.backend._matches_flow(parsed, self.flow))

    def test_direct_tcp_reply_is_correlated_by_reversed_ports_and_ack_session(self):
        flow = FlowKey(ProbeProtocol.TCP, 53000, 443)
        parsed = SimpleNamespace(
            direct_protocol=socket.IPPROTO_TCP,
            direct_source_port=443,
            direct_destination_port=53000,
            session_verified=True,
        )
        self.assertTrue(self.backend._matches_flow(parsed, flow))
        parsed.direct_destination_port = 53001
        self.assertFalse(self.backend._matches_flow(parsed, flow))

    def test_minimum_quote_requires_original_destination_flow(self):
        parsed = SimpleNamespace(
            quoted_protocol=socket.IPPROTO_UDP,
            quoted_destination="198.51.100.9",
            quoted_destination_port=33434,
            session_verified=False,
        )
        self.assertFalse(self.backend._matches_flow(parsed, self.flow))

    def test_mutations_capture_address_port_and_dscp(self):
        parsed = SimpleNamespace(
            quoted_source="192.0.2.99",
            quoted_destination="198.51.100.9",
            quoted_dscp_ecn=32,
            quoted_source_port=62000,
            quoted_destination_port=443,
        )
        mutations = self.backend._mutations(parsed, self.flow)
        self.assertEqual(len(mutations), 5)
        self.assertIn("dscp:0->8", mutations)

    def test_rfc2544_fake_ip_addresses_are_diagnosed(self):
        diagnostic = benchmark_address_diagnostic("198.18.6.85", "198.18.0.1")
        self.assertIn("fake-IP TUN", diagnostic)
        self.assertIn("destination=198.18.6.85", diagnostic)
        self.assertIsNone(benchmark_address_diagnostic("1.1.1.1", "10.0.0.2"))

    def test_kernel_tcp_refusal_is_positive_endpoint_evidence(self):
        control_socket = mock.Mock()
        control_socket.connect_ex.return_value = errno.ECONNREFUSED
        control_socket.getsockname.return_value = ("192.0.2.10", 60123)
        with mock.patch("stratatrace.backend.socket.socket", return_value=control_socket):
            result = self.backend.run_tcp_connect_control(443, 1.0)
        self.assertEqual(result.status, TcpControlStatus.REFUSED)
        self.assertTrue(result.positive_transport_response)
        control_socket.connect_ex.assert_called_once_with(("203.0.113.9", 443))
        control_socket.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
