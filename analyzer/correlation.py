"""Correlation analysis of stream-cipher combiners and taps.

Building blocks for (fast) correlation attacks and linear distinguishing:
combiner bias, Walsh-based best linear approximation, and heuristic
data/time-complexity estimates.

Convention: the **correlation** ``c = |W(a)| / 2^m`` (Walsh coefficient scaled)
equals ``2*P(f=g) - 1`` for the best linear function ``g``. The **bias** is
``eps = P(f=g) - 1/2 = c / 2``. Complexity estimates below take ``c`` directly.
"""

from __future__ import annotations

import math
from typing import Sequence, Tuple

__all__ = [
    "combiner_bias",
    "best_linear_approximation",
    "correlation_attack_complexity",
    "distinguisher_complexity",
    "correlation_to_security_bits",
]


def combiner_bias(table: Sequence[int]) -> float:
    """Bias eps = P(f=1) - 1/2 of a Boolean function given by its truth table."""
    ones = sum(int(t) & 1 for t in table)
    return ones / len(table) - 0.5


def best_linear_approximation(table: Sequence[int]) -> Tuple[int, float]:
    """Best linear approximation of a Boolean function.

    Returns ``(mask, c)``: ``mask`` selects the linear combination of inputs with
    the largest correlation, and ``c = |W(mask)| / 2^m`` is that correlation
    (``c in [0, 1]``; the corresponding bias is ``c / 2``).
    """
    from .ca_model import walsh_spectrum

    W = walsh_spectrum(table)
    m = len(table).bit_length() - 1
    best_a, best_w = 0, 0
    for a, w in enumerate(W):
        if a == 0:      # skip the constant/DC coefficient
            continue
        if abs(w) > best_w:
            best_a, best_w = a, abs(w)
    return best_a, best_w / float(1 << m)


def correlation_attack_complexity(n: int, c: float, constant: float = 8.0) -> float:
    """Heuristic data complexity (bits) of a (fast) correlation attack, ~ k*n/c^2."""
    if c <= 0:
        return float("inf")
    return constant * n / (c * c)


def distinguisher_complexity(c: float) -> float:
    """Data complexity to distinguish with advantage ~1: N ~ 1/c^2."""
    if c <= 0:
        return float("inf")
    return 1.0 / (c * c)


def correlation_to_security_bits(c: float) -> float:
    """Approximate security level (bits) implied by a distinguisher correlation c."""
    N = distinguisher_complexity(c)
    return 0.0 if N <= 0 else math.log2(N)
