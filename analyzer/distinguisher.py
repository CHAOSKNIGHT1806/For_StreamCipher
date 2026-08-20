"""Distinguishing-attack helpers.

A distinguisher with per-bit correlation ``c`` accumulates a signal-to-noise
ratio ``z = c * sqrt(N)`` over ``N`` keystream bits; ``z ~ 1`` is the threshold
for advantage ~1, and ``N ~ 1/c^2`` is the data complexity. These helpers
produce advantage-vs-data curves and run a battery of simple statistical
distinguishers.
"""

from __future__ import annotations

import math
from typing import List, Sequence

from .stats import autocorrelation, block_chi_square, monobit

__all__ = [
    "linear_distinguisher_z",
    "data_for_advantage",
    "distinguisher_curve",
    "run_statistical_distinguishers",
]


def linear_distinguisher_z(correlation: float, n_bits: int) -> float:
    """Signal-to-noise ratio z = c * sqrt(N) for a linear distinguisher."""
    return correlation * math.sqrt(n_bits)


def data_for_advantage(correlation: float, z_target: float = 1.0) -> float:
    """Data complexity N to reach signal-to-noise z_target."""
    if correlation <= 0:
        return float("inf")
    return (z_target / correlation) ** 2


def distinguisher_curve(correlation: float, n_max: int, points: int = 64):
    """Return (n_values, z_values) for an advantage-vs-data plot."""
    if points <= 1:
        return [n_max], [linear_distinguisher_z(correlation, n_max)]
    step = max(1, n_max // points)
    ns = list(range(step, n_max + 1, step))
    return ns, [linear_distinguisher_z(correlation, n) for n in ns]


def run_statistical_distinguishers(bits: Sequence[int], z_threshold: float = 2.5758) -> List[dict]:
    """Run basic statistical distinguishers and flag deviations from random.

    ``suspicious`` is True when the statistic deviates from the fair-random
    expectation at the ~1% level. This is a *screening* tool, not a proof of
    a distinguishing attack (a real attack needs a targeted statistic and a
    data-complexity analysis).
    """
    b = list(bits)
    n = len(b)
    out: List[dict] = []

    mb = monobit(b)
    out.append({"name": "frequency (monobit)", "value": mb["prop_ones"], "z": mb["z"],
                "suspicious": abs(mb["z"]) > z_threshold})

    for r in autocorrelation(b, max_lag=8):
        z = r["A"] * math.sqrt(n)          # A(k) ~ N(0, 1/n) under H0
        out.append({"name": f"autocorr lag {r['lag']}", "value": r["A"], "z": z,
                    "suspicious": abs(z) > z_threshold})

    bc = block_chi_square(b, 8)
    out.append({"name": "block chi-square (8-bit)", "value": bc["chi2"], "p": bc["p"],
                "z": None, "suspicious": bc["p"] < 0.01})

    return out
