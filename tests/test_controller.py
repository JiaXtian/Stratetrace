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
    def test_tcp_kernel_control_runs_after_all_raw_probe_batches(self):
        class OrderingBackend(ScriptedBackend):
            def __init__(self, fixture):
                super().__init__(fixture)
                self.events = []

            def send_batch(self, specs):
                self.events.append("raw")
                return super().send_batch(specs)

            def run_tcp_connect_control(self, destination_port, timeout):
                self.events.append("control")
                return super().run_tcp_connect_control(destination_port, timeout)

        backend = OrderingBackend(FIXTURES / "silent_tail.json")
        config = TraceConfig(
            protocol=ProbeProtocol.TCP,
            destination_port=443,
            tcp_connect_control=True,
            max_hops=8,
            chunk_size=4,
            seed=7,
        )
        result = TraceController(backend, config).run("control-order")
        self.assertIsNotNone(result.tcp_connect_control)
        self.assertEqual(backend.events[-1], "control")

    def test_interrupt_returns_an_auditable_partial_result(self):
        class InterruptingBackend(ScriptedBackend):
            def __init__(self, fixture):
                super().__init__(fixture)
                self.batch_calls = 0

            def send_batch(self, specs):
                self.batch_calls += 1
                if self.batch_calls == 2:
                    raise KeyboardInterrupt
                return super().send_batch(specs)

        backend = InterruptingBackend(FIXTURES / "transparent.json")
        config = TraceConfig(max_hops=8, chunk_size=4, seed=7)
        result = TraceController(backend, config).run("interrupted")
        self.assertTrue(result.interrupted)
        self.assertEqual(result.probe_count, 4)
        self.assertTrue(any("partial" in item for item in result.warnings))

    def test_transparent_path_stays_direct(self):
        result = run_scenario("transparent")
        self.assertTrue(result.reached)
        self.assertEqual(result.terminal_ttl, 4)
        self.assertTrue(result.segments)
        self.assertTrue(all(item.type == SegmentType.DIRECT for item in result.segments))

    def test_open_ended_silence_is_reported_without_false_opaque_claim(self):
        result = run_scenario("silent_tail")
        silent = [
            item for item in result.segments if item.type == SegmentType.SILENT_TAIL
        ]
        self.assertEqual(len(silent), 1)
        self.assertEqual((silent[0].first_ttl, silent[0].last_ttl), (3, 8))
        self.assertEqual(silent[0].ingress, "10.0.2.1")
        self.assertIsNone(silent[0].egress)
        self.assertFalse(silent[0].certificate.certified)
        self.assertEqual(silent[0].certificate.method, "silent_tail_observation")
        self.assertNotIn(SegmentType.OPAQUE, {item.type for item in result.segments})
        self.assertEqual(result.adaptive_probe_count, 0)

    def test_persistent_silence_and_intermittent_visibility_are_separate_claims(self):
        result = run_scenario("split_visibility")
        types = {item.type for item in result.segments}
        self.assertIn(SegmentType.INTERMITTENT, types)
        self.assertIn(SegmentType.OPAQUE, types)
        opaque = next(item for item in result.segments if item.type == SegmentType.OPAQUE)
        self.assertEqual(opaque.certificate.method, "flow_variant_coverage")
        self.assertTrue(opaque.certificate.certified)

    def test_identical_visibility_claims_are_coalesced_with_all_reasons(self):
        result = run_scenario("duplicate_visibility")
        intermittent = [
            item for item in result.segments if item.type == SegmentType.INTERMITTENT
        ]
        self.assertEqual(len(intermittent), 1)
        self.assertIn("flow-sensitive visibility", intermittent[0].reasons)
        self.assertIn("intermittent response visibility", intermittent[0].reasons)

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
        self.assertIn(SegmentType.INTERMITTENT, types)
        intermittent = next(
            item for item in result.segments if item.type == SegmentType.INTERMITTENT
        )
        self.assertEqual(intermittent.certificate.method, "flow_variant_coverage")

    def test_loss_is_not_mislabeled_as_path_instability_and_mutation_is_localized(self):
        backend = ScriptedBackend(FIXTURES / "realistic_lossy_mutable.json")
        config = TraceConfig(
            max_hops=30,
            chunk_size=8,
            baseline_rounds=2,
            temporal_samples=3,
            canary_flows=1,
            min_detectable_probability=0.25,
            miss_probability=0.10,
            max_probes=512,
            seed=7,
        )
        result = TraceController(backend, config).run("baidu-like")
        types = [item.type for item in result.segments]
        self.assertNotIn(SegmentType.UNSTABLE, types)
        self.assertIn(SegmentType.MUTABLE, types)
        self.assertIn(SegmentType.INTERMITTENT, types)
        self.assertIn(SegmentType.MULTIPATH, types)
        mutation = next(item for item in result.segments if item.type == SegmentType.MUTABLE)
        self.assertEqual((mutation.first_ttl, mutation.last_ttl), (10, 12))
        multipath = next(
            item for item in result.segments if item.type == SegmentType.MULTIPATH
        )
        self.assertEqual((multipath.first_ttl, multipath.last_ttl), (11, 13))
        self.assertEqual(multipath.branches[0][0], 12)
        self.assertEqual(len(multipath.branches[0][1]), 2)
        self.assertIsNotNone(multipath.ingress)
        intermittent = [
            item for item in result.segments if item.type == SegmentType.INTERMITTENT
        ]
        self.assertEqual(len(intermittent), 2)
        self.assertTrue(all(item.empirical_stability == 1.0 for item in intermittent))
        self.assertTrue(all(item.response_rate < 1.0 for item in intermittent))
        self.assertLess(result.probe_count, 130)
        self.assertEqual(result.probed_max_ttl, 30)
        self.assertFalse(result.reached)
        self.assertTrue(any("silently filter" in item for item in result.warnings))

    def test_time_axis_identifies_instability(self):
        result = run_scenario("unstable")
        self.assertIn(SegmentType.UNSTABLE, {item.type for item in result.segments})

    def test_quoted_header_change_identifies_mutable_boundary(self):
        result = run_scenario("mutable")
        mutable = next(item for item in result.segments if item.type == SegmentType.MUTABLE)
        self.assertEqual(mutable.certificate.method, "fixed_flow_repeatability")
        self.assertEqual(result.adaptive_probe_count, 3)

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
        self.assertIsNotNone(result.termination)
        self.assertEqual(result.termination.icmp_code, 13)


if __name__ == "__main__":
    unittest.main()
