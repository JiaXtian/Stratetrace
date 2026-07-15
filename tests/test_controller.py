import unittest
from pathlib import Path

from stratatrace.backend import ScriptedBackend
from stratatrace.controller import TraceConfig, TraceController
from stratatrace.model import ProbeProtocol, SegmentType


FIXTURES = Path(__file__).parent / "fixtures"


def run_scenario(name: str):
    backend = ScriptedBackend(FIXTURES / f"{name}.json")
    config = TraceConfig(
        protocol=ProbeProtocol.UDP,
        max_hops=8,
        chunk_size=4,
        baseline_rounds=2,
        canary_flows=1,
        min_detectable_probability=0.5,
        miss_probability=0.25,
        max_probes=128,
        seed=7,
    )
    return TraceController(backend, config).run(name)


class ControllerTests(unittest.TestCase):
    def test_transparent_path_stays_direct(self):
        result = run_scenario("transparent")
        self.assertTrue(result.reached)
        self.assertEqual(result.terminal_ttl, 4)
        self.assertTrue(result.segments)
        self.assertTrue(all(item.type == SegmentType.DIRECT for item in result.segments))

    def test_zero_response_stops_after_one_sweep_without_false_direct_segment(self):
        result = run_scenario("all_timeout")
        self.assertFalse(result.reached)
        self.assertEqual(result.probe_count, 8)
        self.assertEqual(result.adaptive_probe_count, 0)
        self.assertFalse(result.segments)
        self.assertTrue(any("No ICMP response" in item for item in result.warnings))

    def test_global_cap_does_not_spend_more_when_no_boundary_is_visible(self):
        backend = ScriptedBackend(FIXTURES / "all_timeout.json")
        config = TraceConfig(
            max_hops=8,
            chunk_size=4,
            global_cap=True,
            min_detectable_probability=0.5,
            miss_probability=0.25,
            max_probes=128,
            seed=7,
        )
        result = TraceController(backend, config).run("all-timeout")
        self.assertEqual(result.probe_count, 8)
        self.assertFalse(result.segments)

    def test_opaque_gap_has_explicit_mpls_evidence(self):
        result = run_scenario("opaque")
        opaque = [item for item in result.segments if item.type == SegmentType.OPAQUE]
        self.assertEqual(len(opaque), 1)
        self.assertTrue(opaque[0].certificate.certified)
        self.assertIn("MPLS", opaque[0].explicit_mechanism)

    def test_flow_axis_identifies_multipath(self):
        result = run_scenario("ecmp")
        self.assertIn(SegmentType.MULTIPATH, {item.type for item in result.segments})

    def test_flow_dependent_loss_is_not_overclaimed_as_multipath(self):
        result = run_scenario("flow_loss")
        types = {item.type for item in result.segments}
        self.assertNotIn(SegmentType.MULTIPATH, types)
        self.assertIn(SegmentType.UNKNOWN, types)

    def test_time_axis_identifies_instability(self):
        result = run_scenario("unstable")
        self.assertIn(SegmentType.UNSTABLE, {item.type for item in result.segments})

    def test_quoted_header_change_identifies_mutable_boundary(self):
        result = run_scenario("mutable")
        self.assertIn(SegmentType.MUTABLE, {item.type for item in result.segments})

    def test_budget_limited_result_is_never_certified(self):
        backend = ScriptedBackend(FIXTURES / "opaque.json")
        config = TraceConfig(
            max_hops=8,
            chunk_size=4,
            baseline_rounds=2,
            canary_flows=1,
            min_detectable_probability=0.25,
            miss_probability=0.10,
            max_probes=14,
            seed=7,
        )
        result = TraceController(backend, config).run("opaque")
        opaque = next(item for item in result.segments if item.type == SegmentType.OPAQUE)
        self.assertFalse(opaque.certificate.certified)
        self.assertTrue(any("budget" in item.lower() for item in result.warnings))

    def test_probe_accounting(self):
        result = run_scenario("opaque")
        self.assertEqual(result.probe_count, len(result.observations))
        self.assertEqual(
            result.probe_count,
            result.baseline_probe_count + result.adaptive_probe_count,
        )

    def test_intermediate_unreachable_stops_but_does_not_claim_reached(self):
        result = run_scenario("unreachable")
        self.assertFalse(result.reached)
        self.assertEqual(result.terminal_ttl, 2)


if __name__ == "__main__":
    unittest.main()
