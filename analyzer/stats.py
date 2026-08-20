"""Basic statistical analysis of binary keystreams.

Focused, lightweight tests that complement the full NIST SP 800-22 battery:
frequency (monobit), autocorrelation, chi-square block uniformity, and runs.
"""

from __future__ import annotations

import math
from typing import Dict, List, Sequence

__all__ = [
    "monobit",
    "autocorrelation",
    "runs_test",
    "block_chi_square",
    "summary_stats",
]


def _bits(seq: Sequence[int]) -> List[int]:
    return [int(b) & 1 for b in seq]


def monobit(seq: Sequence[int]) -> Dict[str, float]:
    """Frequency (monobit) test: proportion of ones and a z-score.

    Under H0 (fair), z ~ N(0,1). |z| > 2.5758 rejects at 1% (two-sided).
    """
    s = _bits(seq)
    n = len(s)
    ones = sum(s)
    p = ones / n
    z = (ones - n / 2) / math.sqrt(n / 4) if n else 0.0
    return {"n": n, "ones": ones, "prop_ones": p, "z": z}


def autocorrelation(seq: Sequence[int], max_lag: int = 100) -> List[Dict[str, float]]:
    """Return normalized autocorrelation A(k) for lags k = 1..max_lag.

    A(k) = 1/n * sum_i (2*s[i]-1)(2*s[i+k]-1). For random data E[A(k)] = 0 and
    Var[A(k)] ~ 1/n, so |A(k)| > 2.5758/sqrt(n) rejects at 1%.
    """
    s = _bits(seq)
    n = len(s)
    x = [2 * b - 1 for b in s]  # map to +1/-1
    out: List[Dict[str, float]] = []
    for k in range(1, max_lag + 1):
        if k >= n:
            break
        acc = 0
        for i in range(n - k):
            acc += x[i] * x[i + k]
        out.append({"lag": k, "A": acc / (n - k)})
    return out


def runs_test(seq: Sequence[int]) -> Dict[str, float]:
    """Wald-Wolfowitz runs test (counts of runs, expected under H0)."""
    s = _bits(seq)
    n = len(s)
    if n == 0:
        return {"runs": 0, "z": 0.0}
    runs = 1
    for i in range(1, n):
        if s[i] != s[i - 1]:
            runs += 1
    n1 = sum(s)
    n0 = n - n1
    if n1 == 0 or n0 == 0:
        return {"runs": runs, "z": float("nan")}
    mu = 2 * n1 * n0 / n + 1
    var = 2 * n1 * n0 * (2 * n1 * n0 - n) / (n * n * (n - 1))
    z = (runs - mu) / math.sqrt(var)
    return {"runs": runs, "mu": mu, "z": z}


def block_chi_square(seq: Sequence[int], block_bits: int = 8) -> Dict[str, float]:
    """Chi-square uniformity of non-overlapping ``block_bits`` blocks.

    Returns chi2 and the p-value for ``2**block_bits - 1`` degrees of freedom.
    """
    s = _bits(seq)
    n = len(s)
    nb = 1 << block_bits
    counts = [0] * nb
    total = 0
    for i in range(0, n - block_bits + 1, block_bits):
        v = 0
        for j in range(block_bits):
            v = (v << 1) | s[i + j]
        counts[v] += 1
        total += 1
    if total == 0:
        return {"chi2": 0.0, "p": 1.0, "blocks": 0}
    expected = total / nb
    chi2 = sum((c - expected) ** 2 / expected for c in counts)
    # Regularized incomplete gamma upper = Q(df/2, chi2/2)
    p = _gamma_q((nb - 1) / 2, chi2 / 2)
    return {"chi2": chi2, "p": p, "blocks": total, "df": nb - 1}


def _gamma_q(a: float, x: float) -> float:
    """Upper regularized incomplete gamma Q(a, x) (Lentz + series, real x>=0)."""
    # Guard against extremes.
    if x < 0:
        return float("nan")
    if a <= 0:
        return float("nan")
    if x < a + 1:
        return 1.0 - _gamma_p_series(a, x)
    return _gamma_q_cf(a, x)


def _gamma_p_series(a: float, x: float, iters: int = 200) -> float:
    ap = a
    s = term = 1.0 / a
    for _ in range(iters):
        ap += 1
        term *= x / ap
        s += term
        if abs(term) < abs(s) * 1e-15:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_q_cf(a: float, x: float, iters: int = 200) -> float:
    # Continued fraction for Q(a, x).
    tiny = 1e-300
    b = x + 1 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, iters + 1):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def summary_stats(seq: Sequence[int], max_lag: int = 32, block_bits: int = 8) -> Dict:
    """Convenience: run all basic stats and return a flat dict."""
    return {
        "monobit": monobit(seq),
        "runs": runs_test(seq),
        "block_chi_square": block_chi_square(seq, block_bits),
        "autocorr": autocorrelation(seq, max_lag),
    }
