import socket
import unittest
from types import SimpleNamespace

from stratatrace.backend import RawIPv4Backend
from stratatrace.model import FlowKey, ProbeProtocol


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
        self.assertIn("dscp-ecn:0->32", mutations)


if __name__ == "__main__":
    unittest.main()
