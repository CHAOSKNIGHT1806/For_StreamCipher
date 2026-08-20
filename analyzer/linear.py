"""Berlekamp-Massey algorithm and linear complexity analysis over GF(2)."""

from __future__ import annotations

from typing import List, Sequence, Tuple

__all__ = [
    "berlekamp_massey",
    "linear_complexity",
    "linear_complexity_profile",
    "connection_polynomial_to_taps",
]


def berlekamp_massey(seq: Sequence[int]) -> Tuple[int, List[int]]:
    """Return ``(L, C)`` for a binary sequence.

    ``L`` is the linear complexity (length of the shortest LFSR that generates
    ``seq``). ``C`` is the connection polynomial in coefficient-list form with
    ``C[0] = 1`` and ``len(C) == L + 1``; the recurrence is

        s[n] = C[1]*s[n-1] + C[2]*s[n-2] + ... + C[L]*s[n-L]  (mod 2)

    ``seq`` is a sequence of ints in {0, 1}.
    """
    s = [int(b) & 1 for b in seq]
    n = len(s)

    C = [1]        # current connection polynomial (constant term first)
    B = [1]        # previous polynomial
    L = 0          # current linear complexity
    m = 1          # shift offset
    b = 1          # last non-zero discrepancy (always 1 over GF(2) when used)

    for N in range(n):
        # discrepancy d = s[N] XOR sum_{i=1..L} C[i] * s[N-i]
        d = s[N]
        for i in range(1, L + 1):
            d ^= C[i] & s[N - i]

        if d:
            T = C[:]
            need = len(B) + m
            if len(C) < need:
                C += [0] * (need - len(C))
            for i in range(len(B)):
                C[i + m] ^= B[i]
            if 2 * L <= N:
                L = N + 1 - L
                B = T
                b = d
                m = 1
            else:
                m += 1
        else:
            m += 1

    return L, C[: L + 1]


def linear_complexity(seq: Sequence[int]) -> int:
    """Return just the linear complexity L."""
    return berlekamp_massey(seq)[0]


def linear_complexity_profile(seq: Sequence[int]) -> List[int]:
    """Return L_k for every prefix s[:k], k = 1..len(seq).

    For a random sequence, L_k should hug the line k/2.
    """
    s = list(seq)
    profile: List[int] = []
    for k in range(1, len(s) + 1):
        profile.append(berlekamp_massey(s[:k])[0])
    return profile


def connection_polynomial_to_taps(C: Sequence[int]) -> List[int]:
    """Return tap positions (1-indexed) for a connection polynomial C.

    ``C`` uses the same convention as :func:`berlekamp_massey` (C[0] = 1 is the
    constant term). The returned taps are the indices i >= 1 where C[i] == 1.
    """
    return [i for i in range(1, len(C)) if C[i]]
