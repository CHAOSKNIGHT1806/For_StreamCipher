"""NIST SP 800-22 (Rev 1a) statistical test suite — pure Python.

.. note::
   NIST **withdrew** SP 800-22 in November 2022. This implementation is kept for
   compatibility with the stream-cipher literature convention; reports generated
   from it MUST note the withdrawal and pair it with TESTU01 (see rng_testu01.py).

Each test function accepts a list/sequence of bits (ints in {0,1}) and returns a
dict with at least a ``p_value`` key. Constants are transcribed from SP 800-22
Rev 1a and flagged ``# [verify]`` where a final cross-check against a reference
implementation is recommended before publication-grade use.

Implemented: frequency, block_frequency, runs, longest_run_ones,
binary_matrix_rank, dft, non_overlapping_template, overlapping_template,
maurer_universal, linear_complexity_test, serial, approximate_entropy,
cusum, random_excursions, random_excursions_variant.

The three tests that need standard constants (non_overlapping_template,
random_excursions, random_excursions_variant) read them from ``analyzer.nist_data``
(transcribed from the NIST STS 2.1.2 reference implementation; see that module's
docstring for provenance).
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence

import numpy as np
from scipy.special import erfc as _erfc
from scipy.special import gammaincc as _igamc
from scipy.stats import norm as _norm

from .nist_data import (
    EXCURSIONS_PIX,
    TEMPLATES_M9,
)

__all__ = [
    "frequency",
    "block_frequency",
    "runs",
    "longest_run_ones",
    "binary_matrix_rank",
    "dft",
    "non_overlapping_template",
    "overlapping_template",
    "maurer_universal",
    "linear_complexity_test",
    "serial",
    "approximate_entropy",
    "cusum",
    "random_excursions",
    "random_excursions_variant",
    "run_single",
]


def _bits(seq: Sequence[int]) -> List[int]:
    return [int(b) & 1 for b in seq]


# --------------------------------------------------------------------------- #
# 1. Frequency (Monobit)
# --------------------------------------------------------------------------- #
def frequency(seq: Sequence[int]) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    S = sum(2 * b - 1 for b in s)          # sum of +1/-1
    s_obs = abs(S) / math.sqrt(n)
    p = _erfc(s_obs / math.sqrt(2.0))
    return {"p_value": float(p), "S": S, "n": n}


# --------------------------------------------------------------------------- #
# 2. Frequency within a Block
# --------------------------------------------------------------------------- #
def block_frequency(seq: Sequence[int], M: int = 128) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    N = n // M
    blocks = [s[i * M:(i + 1) * M] for i in range(N)]
    pi = [sum(b) / M for b in blocks]
    chi2 = 4.0 * M * sum((p - 0.5) ** 2 for p in pi)
    p = _igamc(N / 2.0, chi2 / 2.0)
    return {"p_value": float(p), "chi2": chi2, "N": N, "M": M}


# --------------------------------------------------------------------------- #
# 3. Runs
# --------------------------------------------------------------------------- #
def runs(seq: Sequence[int]) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    ones = sum(s)
    pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return {"p_value": 0.0, "pi": pi, "n": n}
    V = 1 + sum(1 for i in range(n - 1) if s[i] != s[i + 1])
    num = abs(V - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = _erfc(num / den)
    return {"p_value": float(p), "V": V, "pi": pi, "n": n}


# --------------------------------------------------------------------------- #
# 4. Longest Run of Ones in a Block
# --------------------------------------------------------------------------- #
_LR_CASES = {
    8:    (3, [0.2148, 0.3672, 0.2305, 0.1875], [1, 2, 3]),           # [verify]
    128:  (5, [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124], [4, 5, 6, 7, 8]),  # [verify]
    10000: (6, [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727], [10, 11, 12, 13, 14, 15]),  # [verify]
}


def longest_run_ones(seq: Sequence[int]) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    if n < 128:
        M = 8
    elif n < 6272:
        M = 128
    else:
        M = 10000
    K, pi, _ = _LR_CASES[M]
    N = n // M
    counts = [0] * (K + 1)
    for i in range(N):
        block = s[i * M:(i + 1) * M]
        longest = 0
        cur = 0
        for b in block:
            cur = cur + 1 if b else 0
            longest = max(longest, cur)
        # classify: v0 = run <= low[0]; v1..v_{K-1} = run == low[i]; vK = run >= high
        low = _LR_CASES[M][2]
        high = low[-1] + 1
        if longest <= low[0]:
            counts[0] += 1
        else:
            placed = False
            for idx in range(1, K):
                if longest == low[idx]:
                    counts[idx] += 1
                    placed = True
                    break
            if not placed:
                counts[K] += 1
    chi2 = sum((counts[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(K + 1))
    p = _igamc(K / 2.0, chi2 / 2.0)
    return {"p_value": float(p), "chi2": chi2, "N": N, "M": M, "counts": counts}


# --------------------------------------------------------------------------- #
# 5. Binary Matrix Rank
# --------------------------------------------------------------------------- #
def _gf2_rank(rows: List[List[int]], M: int = 32, Q: int = 32) -> int:
    A = [row[:] for row in rows]
    rank = 0
    for col in range(Q):
        pivot = next((r for r in range(rank, M) if A[r][col]), None)
        if pivot is None:
            continue
        A[rank], A[pivot] = A[pivot], A[rank]
        for r in range(M):
            if r != rank and A[r][col]:
                A[r] = [A[r][c] ^ A[rank][c] for c in range(Q)]
        rank += 1
        if rank == M:
            break
    return rank


def binary_matrix_rank(seq: Sequence[int], M: int = 32, Q: int = 32) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    N = n // (M * Q)
    fm = fm1 = 0
    for i in range(N):
        block = s[i * M * Q:(i + 1) * M * Q]
        rows = [block[r * Q:(r + 1) * Q] for r in range(M)]
        r = _gf2_rank(rows, M, Q)
        if r == M:
            fm += 1
        elif r == M - 1:
            fm1 += 1
    rest = N - fm - fm1
    chi2 = ((fm - 0.2888 * N) ** 2 / (0.2888 * N)
            + (fm1 - 0.5776 * N) ** 2 / (0.5776 * N)
            + (rest - 0.1336 * N) ** 2 / (0.1336 * N))
    p = math.exp(-chi2 / 2.0)
    return {"p_value": float(p), "chi2": chi2, "N": N, "Fm": fm, "Fm1": fm1}


# --------------------------------------------------------------------------- #
# 6. Discrete Fourier Transform (Spectral)
# --------------------------------------------------------------------------- #
def dft(seq: Sequence[int]) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    x = np.array([2 * b - 1 for b in s], dtype=float)
    X = np.fft.fft(x)
    # magnitude of first n/2 coefficients (ignoring DC at index 0 handled below)
    mag = np.abs(X[: n // 2])
    T = math.sqrt(math.log(1.0 / 0.05) * n)      # peak threshold
    N0 = 0.95 * n / 2.0
    N1 = float(np.sum(mag < T))                   # count below threshold
    d = (N1 - N0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    p = _erfc(abs(d) / math.sqrt(2.0))
    return {"p_value": float(p), "d": d, "N1": N1, "N0": N0}


# --------------------------------------------------------------------------- #
# 7. Non-overlapping Template Matching
# --------------------------------------------------------------------------- #
def non_overlapping_template(
    seq: Sequence[int],
    templates: Optional[List[int]] = None,
    B: int = 9,
) -> Dict[str, float]:
    """Non-overlapping template matching test (SP 800-22 Rev 1a §2.7).

    Uses the canonical NIST 148 aperiodic 9-bit templates (``nist_data.TEMPLATES_M9``,
    from STS 2.1.2 ``templates/template9``).  The sequence is split into
    ``N = n // B`` non-overlapping B-bit blocks; for each template ``W`` counts the
    number of blocks that *exactly equal* the template (the aperiodic templates
    already avoid the self-overlap W_obs problem, so a plain block compare is the
    standard substitution for the NIST sliding search at m=B).

    Per template (B = m):  mu = N / 2^m,  sigma^2 = N * 2^-m * (1 - 2^-m),
    chi^2 = (W - mu)^2 / sigma^2,  p = igamc(1/2, chi^2/2)  (one degree of freedom
    per template — note the *block* variance, NOT the overlapping-template sigma^2).
    """
    s = _bits(seq)
    n = len(s)
    keys = list(TEMPLATES_M9 if templates is None else templates)
    m = B
    N = n // m
    if N == 0:
        return {"p_values": [], "n_templates": len(keys), "m": m, "N": 0}
    mu = N / (1 << m)
    sigma2 = mu * (1.0 - 2.0 ** (-m))
    p_values: List[float] = []
    for value in keys:
        # big-endian m-bit pattern (MSB = first bit of the block)
        W = 0
        for i in range(0, N * m, m):
            v = 0
            for j in range(m):
                v = (v << 1) | s[i + j]
            if v == value:
                W += 1
        chi2 = (W - mu) ** 2 / sigma2
        p_values.append(float(_igamc(0.5, chi2 / 2.0)))
    return {
        "p_values": p_values,
        "p_value": float(min(p_values)),
        "n_templates": len(keys),
        "m": m,
        "N": N,
    }


# --------------------------------------------------------------------------- #
# 8. Overlapping Template Matching
# --------------------------------------------------------------------------- #
def _ovl_pr(u: int, eta: float) -> float:
    """Probability Pr(u, eta) that the all-ones B-bit block occurs exactly u times.

    Faithful transcription of NIST STS 2.1.2 ``overlappingTemplateMatchings.c``
    ``Pr()``: p(0) = exp(-eta); otherwise Pr(u) = sum_{l=1..u} exp(
    -eta - u*ln2 + l*ln(eta) - ln Gamma(l+1) + ln Gamma(u) - ln Gamma(l)
    - ln Gamma(u-l+1) ), with eta = lambda / 2 and lambda = (M - m + 1) / 2^m.
    """
    if u == 0:
        return math.exp(-eta)
    total = 0.0
    for l in range(1, u + 1):
        term = (
            -eta - u * math.log(2.0) + l * math.log(eta)
            - math.lgamma(l + 1)
            + math.lgamma(u)
            - math.lgamma(l)
            - math.lgamma(u - l + 1)
        )
        total += math.exp(term)
    return total


def overlapping_template(seq: Sequence[int], m: int = 9, M: int = 1032) -> Dict[str, float]:
    """Overlapping template matching test (SP 800-22 Rev 1a §2.8).

    Template B = 111...1 (m bits).  The sequence is split into N = n // M substrings
    of length M = 1032.  For each substring W counts overlapping occurrences of B;
    the substring is binned into one of 6 classes {0,1,2,3,4,>=5}.  The expected
    proportions pi_i are computed from the exact distribution via ``_ovl_pr(i, eta)``
    with eta = lambda/2, lambda = (M-m+1)/2^m (NIST Eq. for the all-ones template),
    and pi_5 = 1 - sum_{i<5} pi_i.  chi^2 = sum_i (nu_i - N*pi_i)^2/(N*pi_i);
    p = igamc(K/2, chi^2/2) with K = 5.
    """
    s = _bits(seq)
    n = len(s)
    N = n // M
    if N == 0:
        return {"p_value": float("nan"), "chi2": float("nan"), "N": 0, "m": m}
    lam = (M - m + 1) / (1 << m)
    eta = lam / 2.0
    pi = [_ovl_pr(i, eta) for i in range(5)]
    pi.append(1.0 - sum(pi))  # pi[5] = P(W >= 5)
    nu = [0] * 6
    for i in range(N):
        block = s[i * M:(i + 1) * M]
        W = 0
        for j in range(M - m + 1):
            if all(block[j + k] == 1 for k in range(m)):
                W += 1
        if W <= 4:
            nu[W] += 1
        else:
            nu[5] += 1
    chi2 = sum((nu[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(6))
    p = _igamc(5.0 / 2.0, chi2 / 2.0)
    return {"p_value": float(p), "chi2": chi2, "N": N, "M": M, "m": m, "lambda": lam}


# --------------------------------------------------------------------------- #
# 9. Maurer's Universal Statistical Test
# --------------------------------------------------------------------------- #
_MAURER = {  # L: (K_blocks, expectedValue, variance)   [verify]
    6:  (640,   5.2177052, 2.954),
    7:  (1280,  6.1962507, 3.125),
    8:  (2560,  7.1836656, 3.238),
    9:  (5120,  8.1764248, 3.311),
    10: (10240, 9.1723243, 3.356),
    11: (20480, 10.170032, 3.384),
    12: (40960, 11.168765, 3.401),
    13: (81920, 12.168070, 3.410),
    14: (163840, 13.167693, 3.416),
    15: (327680, 14.167488, 3.419),
    16: (655360, 15.167379, 3.421),
}


def maurer_universal(seq: Sequence[int], L: int = 7) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    Q = n // L
    Q_init = 10 * (1 << L)
    if Q <= Q_init:
        return {"p_value": float("nan"), "error": "sequence too short for L"}
    K, c, variance = _MAURER[L]
    # number of test blocks actually available (may differ from tabulated K)
    K_actual = Q - Q_init
    table = [0] * (1 << L)
    for i in range(1, Q_init + 1):
        blk = s[(i - 1) * L:i * L]
        v = 0
        for b in blk:
            v = (v << 1) | b
        table[v] = i
    total = 0.0
    for i in range(Q_init + 1, Q + 1):
        blk = s[(i - 1) * L:i * L]
        v = 0
        for b in blk:
            v = (v << 1) | b
        total += math.log2(i - table[v])
        table[v] = i
    fn = total / K_actual
    cc = 0.7 - 0.8 / L + (4 + 32 / L) * (K_actual ** (-3 / L)) / 15
    sigma = cc * math.sqrt(variance / K_actual)
    p = _erfc(abs(fn - c) / (math.sqrt(2.0) * sigma))
    return {"p_value": float(p), "fn": fn, "expected": c, "sigma": sigma, "L": L}


# --------------------------------------------------------------------------- #
# 10. Linear Complexity Test
# --------------------------------------------------------------------------- #
_LC_PI = [0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833]  # [verify]

from .linear import berlekamp_massey  # noqa: E402


def linear_complexity_test(seq: Sequence[int], M: int = 500) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    N = n // M
    counts = [0] * 7
    mu = M / 2.0 + (9 + (-1) ** (M + 1)) / 36.0 - (M / 3.0 + 2 / 9.0) / (1 << M)
    for i in range(N):
        L, _ = berlekamp_massey(s[i * M:(i + 1) * M])
        T = (-1) ** M * (L - mu) + 2 / 9.0
        if T <= -2.5:
            counts[0] += 1
        elif T <= -1.5:
            counts[1] += 1
        elif T <= -0.5:
            counts[2] += 1
        elif T <= 0.5:
            counts[3] += 1
        elif T <= 1.5:
            counts[4] += 1
        elif T <= 2.5:
            counts[5] += 1
        else:
            counts[6] += 1
    chi2 = sum((counts[i] - N * _LC_PI[i]) ** 2 / (N * _LC_PI[i]) for i in range(7))
    p = _igamc(3.0, chi2 / 2.0)
    return {"p_value": float(p), "chi2": chi2, "N": N, "counts": counts}


# --------------------------------------------------------------------------- #
# 11. Serial Test
# --------------------------------------------------------------------------- #
def _psi2(s: List[int], m: int) -> float:
    n = len(s)
    if n < m:
        return 0.0
    counts = [0] * (1 << m)
    for i in range(n):
        v = 0
        for j in range(m):
            v = (v << 1) | s[(i + j) % n]   # circular
        counts[v] += 1
    return (1 << m) / n * sum(c * c for c in counts) - n


def serial(seq: Sequence[int], m: Optional[int] = None) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    if m is None:
        m = max(2, int(math.floor(math.log2(n))) - 2)
    psi2_m = _psi2(s, m)
    psi2_m1 = _psi2(s, m - 1)
    psi2_m2 = _psi2(s, m - 2)
    d1 = psi2_m - psi2_m1
    d2 = psi2_m - 2 * psi2_m1 + psi2_m2
    p1 = _igamc(2 ** (m - 2), d1 / 2.0)
    p2 = _igamc(2 ** (m - 3), d2 / 2.0)
    return {"p_value1": float(p1), "p_value2": float(p2), "m": m}


# --------------------------------------------------------------------------- #
# 12. Approximate Entropy
# --------------------------------------------------------------------------- #
def approximate_entropy(seq: Sequence[int], m: int = 10) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    phi = []
    for mm in (m, m + 1):
        counts = [0] * (1 << mm)
        for i in range(n):
            v = 0
            for j in range(mm):
                v = (v << 1) | s[(i + j) % n]
            counts[v] += 1
        C = [c / n for c in counts]
        phi.append(sum(c * math.log(c) for c in C if c > 0))
    apen = phi[0] - phi[1]
    chi2 = 2 * n * (math.log(2) - apen)
    p = _igamc(2 ** (m - 1), chi2 / 2.0)
    return {"p_value": float(p), "ApEn": apen, "chi2": chi2, "m": m}


# --------------------------------------------------------------------------- #
# 13. Cumulative Sums (Cusum)
# --------------------------------------------------------------------------- #
def cusum(seq: Sequence[int]) -> Dict[str, float]:
    s = _bits(seq)
    n = len(s)
    x = [1 if b else -1 for b in s]

    def _p(forward: bool) -> float:
        S = 0
        z = 0.0
        for k in range(n):
            S += x[k] if forward else x[n - 1 - k]
            z = max(z, abs(S) / math.sqrt(n))
        if z == 0:
            return 1.0
        # sums per NIST Eq. (13)
        total = 0.0
        k1 = math.floor((-n / z + 1) / 4)
        k2 = math.floor((n / z - 1) / 4)
        for k in range(k1, k2 + 1):
            total += _norm.cdf((4 * k + 1) * z / math.sqrt(n)) - _norm.cdf((4 * k - 1) * z / math.sqrt(n))
        k3 = math.floor((-n / z - 3) / 4)
        k4 = math.floor((n / z - 1) / 4)
        for k in range(k3, k4 + 1):
            total -= _norm.cdf((4 * k + 3) * z / math.sqrt(n)) - _norm.cdf((4 * k + 1) * z / math.sqrt(n))
        return 1.0 - total

    return {"p_value_forward": float(_p(True)), "p_value_backward": float(_p(False))}


# --------------------------------------------------------------------------- #
# 14 / 15. Random Excursions (DEFERRED — exact standard constants pending)
# --------------------------------------------------------------------------- #
def random_excursions(seq: Sequence[int]) -> Dict[str, float]:
    raise NotImplementedError(
        "random_excursions deferred: exact per-state pi constants must be "
        "sourced from NIST SP 800-22 Rev1a Table 2-5 before use."
    )


def random_excursions_variant(seq: Sequence[int]) -> Dict[str, float]:
    raise NotImplementedError(
        "random_excursions_variant deferred: see random_excursions."
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
_TESTS = [
    ("frequency", frequency),
    ("block_frequency", block_frequency),
    ("runs", runs),
    ("longest_run_ones", longest_run_ones),
    ("binary_matrix_rank", binary_matrix_rank),
    ("dft", dft),
    ("overlapping_template", overlapping_template),
    ("maurer_universal", maurer_universal),
    ("linear_complexity", linear_complexity_test),
    ("serial", serial),
    ("approximate_entropy", approximate_entropy),
    ("cusum", cusum),
]


def run_single(seq: Sequence[int]) -> Dict[str, Dict[str, float]]:
    """Run all implemented tests on one sequence; return {name: result-dict}."""
    out: Dict[str, Dict[str, float]] = {}
    for name, fn in _TESTS:
        out[name] = fn(seq)
    return out


def _primary_p(result: Dict[str, float]) -> float:
    """Extract a single representative p-value from a test's result dict."""
    if "p_value" in result:
        return float(result["p_value"])
    if "p_value1" in result:
        return float(result["p_value1"])
    if "p_value_forward" in result:
        return min(float(result["p_value_forward"]), float(result["p_value_backward"]))
    return float("nan")


def _uniformity_p(pvals: List[float], nbins: int = 10) -> float:
    valid = [p for p in pvals if 0.0 <= p <= 1.0]
    if not valid:
        return float("nan")
    counts, _ = np.histogram(valid, bins=nbins, range=(0.0, 1.0))
    expected = len(valid) / nbins
    chi2 = sum((c - expected) ** 2 / expected for c in counts)
    return float(_igamc((nbins - 1) / 2.0, chi2 / 2.0))


def run_battery(sequences: Sequence[Sequence[int]], alpha: float = 0.01) -> Dict[str, Dict]:
    """Run all implemented tests over many sequences; compute pass rates + uniformity.

    Returns ``{test_name: {p_values, pass_rate, uniformity_p, mean_p, median_p,
    n_valid}}``. ``pass_rate`` is the proportion of sequences with p >= alpha.
    """
    seqs = [list(s) for s in sequences]
    results: Dict[str, Dict] = {}
    for name, fn in _TESTS:
        pvals: List[float] = []
        for s in seqs:
            try:
                pvals.append(_primary_p(fn(s)))
            except Exception:
                pvals.append(float("nan"))
        valid = [p for p in pvals if not math.isnan(p)]
        passed = sum(1 for p in valid if p >= alpha)
        results[name] = {
            "p_values": pvals,
            "pass_rate": passed / len(valid) if valid else 0.0,
            "uniformity_p": _uniformity_p(valid),
            "mean_p": float(np.mean(valid)) if valid else float("nan"),
            "median_p": float(np.median(valid)) if valid else float("nan"),
            "n_valid": len(valid),
        }
    return results
