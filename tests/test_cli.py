import contextlib
import io
import json
import unittest
from pathlib import Path

from stratatrace.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


class CliTests(unittest.TestCase):
    def test_simulated_json_is_valid_and_reached(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(
                [
                    "--simulate",
                    str(FIXTURES / "transparent.json"),
                    "--max-hops",
                    "8",
                    "--json",
                    "example.invalid",
                ]
            )
        self.assertEqual(status, 0)
        document = json.loads(stdout.getvalue())
        self.assertTrue(document["reached"])
        self.assertNotIn("observations", document)

    def test_invalid_probability_is_rejected(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(
                [
                    "--simulate",
                    str(FIXTURES / "transparent.json"),
                    "--min-detectable-prob",
                    "1.0",
                    "example.invalid",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("strictly between 0 and 1", stderr.getvalue())

    def test_fake_ip_tun_address_fails_before_raw_socket_creation(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = main(["--source", "198.18.0.1", "198.18.6.85"])
        self.assertEqual(status, 2)
        self.assertIn("fake-IP TUN", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
