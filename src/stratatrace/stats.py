"""Small, dependency-free statistical bounds used by CAP."""

from __future__ import annotations

import math


def validate_probability(value: float, name: str) -> None:
    if not 0.0 < value < 1.0:
        raise ValueError(f"{name} must be strictly between 0 and 1")


def required_samples(min_probability: float, miss_probability: float) -> int:
    """Samples needed so (1-p_min)^n <= delta.

    Under independent sampling (or uniform sampling without replacement), an
    outcome whose selection mass is at least ``min_probability`` is missed in
    all n trials with probability no greater than ``miss_probability``.
    """

    validate_probability(min_probability, "min_probability")
    validate_probability(miss_probability, "miss_probability")
    return max(
        1,
        int(math.ceil(math.log(miss_probability) / math.log1p(-min_probability))),
    )


def miss_probability_bound(min_probability: float, samples: int) -> float:
    validate_probability(min_probability, "min_probability")
    if samples < 0:
        raise ValueError("samples must be non-negative")
    return math.pow(1.0 - min_probability, samples)


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple:
    """Two-sided Wilson score interval, used only as descriptive stability."""

    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("expected 0 <= successes <= trials and trials > 0")
    estimate = successes / trials
    z2 = z * z
    denominator = 1.0 + z2 / trials
    centre = (estimate + z2 / (2.0 * trials)) / denominator
    radius = (
        z
        * math.sqrt((estimate * (1.0 - estimate) + z2 / (4.0 * trials)) / trials)
        / denominator
    )
    return max(0.0, centre - radius), min(1.0, centre + radius)
