import unittest

from stratatrace.stats import miss_probability_bound, required_samples, wilson_interval


class StatsTests(unittest.TestCase):
    def test_required_samples_satisfies_bound_minimally(self):
        for probability, delta in ((0.5, 0.25), (0.25, 0.1), (0.1, 0.01)):
            samples = required_samples(probability, delta)
            self.assertLessEqual(miss_probability_bound(probability, samples), delta)
            if samples > 1:
                self.assertGreater(miss_probability_bound(probability, samples - 1), delta)

    def test_documented_default_sample_count(self):
        self.assertEqual(required_samples(0.25, 0.10), 9)

    def test_wilson_interval_is_bounded(self):
        lower, upper = wilson_interval(8, 10)
        self.assertLess(lower, 0.8)
        self.assertGreater(upper, 0.8)
        self.assertGreaterEqual(lower, 0.0)
        self.assertLessEqual(upper, 1.0)


if __name__ == "__main__":
    unittest.main()
