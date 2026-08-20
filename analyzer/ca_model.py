"""Cellular-automaton (CA) modeling utilities.

Provides rule/ANF conversion, algebraic degree and linearity checks, Walsh
spectrum / nonlinearity / correlation immunity (for linear and correlation
attack analysis), CA step simulation with boundary conditions, and a
linear-degeneration screen that flags when a CA collapses to a linear system
(breakable immediately by Berlekamp-Massey).

Pure Python + standard library (numpy not required).
"""

from __future__ import annotations

from typing import List, Optional, Sequence

__all__ = [
    "rule_number_to_table",
    "table_to_rule_number",
    "anf_from_table",
    "anf_to_string",
    "algebraic_degree",
    "is_affine",
    "is_linear",
    "walsh_spectrum",
    "nonlinearity",
    "correlation_immunity",
    "ca_step",
    "ca_keystream",
    "screen_linear_degeneration",
]


# --------------------------------------------------------------------------- #
# Rule <-> truth table
# --------------------------------------------------------------------------- #
def rule_number_to_table(rule: int) -> List[int]:
    """Elementary CA rule number -> 8-entry truth table.

    Table index is ``(l << 2) | (c << 1) | r`` for the left/center/right
    neighbors, i.e. index 0 = neighborhood (0,0,0), index 7 = (1,1,1).
    """
    if not (0 <= rule < 256):
        raise ValueError("elementary CA rule must be in [0, 255]")
    return [(rule >> i) & 1 for i in range(8)]


def table_to_rule_number(table: Sequence[int]) -> int:
    r = 0
    for i, b in enumerate(table):
        r |= (int(b) & 1) << i
    return r


# --------------------------------------------------------------------------- #
# Algebraic normal form (ANF)
# --------------------------------------------------------------------------- #
def anf_from_table(table: Sequence[int]) -> List[int]:
    """Mobius transform: truth table -> ANF coefficient vector (length 2^m).

    ``anf[idx]`` is the coefficient of the monomial formed by the variables whose
    bit positions are set in ``idx``.
    """
    a = [int(t) & 1 for t in table]
    n = len(a)
    m = n.bit_length() - 1
    if (1 << m) != n:
        raise ValueError("table length must be a power of two")
    for i in range(m):
        step = 1 << i
        for j in range(0, n, step << 1):
            for k in range(j, j + step):
                a[k + step] ^= a[k]
    return a


def anf_to_string(anf: Sequence[int], names: Optional[Sequence[str]] = None) -> str:
    m = len(anf).bit_length() - 1
    nm = list(names) if names is not None else [f"x{i}" for i in range(m)]
    terms: List[str] = []
    for idx, c in enumerate(anf):
        if c:
            vs = [nm[i] for i in range(m) if (idx >> i) & 1]
            terms.append("*".join(vs) if vs else "1")
    return " + ".join(terms) if terms else "0"


def algebraic_degree(anf: Sequence[int]) -> int:
    deg = 0
    for idx, c in enumerate(anf):
        if c:
            deg = max(deg, bin(idx).count("1"))
    return deg


def is_affine(anf: Sequence[int]) -> bool:
    return algebraic_degree(anf) <= 1


def is_linear(anf: Sequence[int]) -> bool:
    """Linear (homogeneous) iff no constant term and degree <= 1."""
    if anf[0]:
        return False
    return algebraic_degree(anf) <= 1


# --------------------------------------------------------------------------- #
# Walsh spectrum, nonlinearity, correlation immunity
# --------------------------------------------------------------------------- #
def walsh_spectrum(table: Sequence[int]) -> List[int]:
    F = [1 - 2 * (int(t) & 1) for t in table]
    n = len(F)
    m = n.bit_length() - 1
    W = F[:]
    for i in range(m):
        step = 1 << i
        for j in range(0, n, step << 1):
            for k in range(j, j + step):
                a, b = W[k], W[k + step]
                W[k] = a + b
                W[k + step] = a - b
    return W


def nonlinearity(table: Sequence[int]) -> int:
    W = walsh_spectrum(table)
    return (len(table) // 2) - max(abs(w) for w in W) // 2


def correlation_immunity(table: Sequence[int]) -> int:
    """Highest t such that f is t-th order correlation immune (Walsh zeros)."""
    W = walsh_spectrum(table)
    t = 0
    for a, w in enumerate(W):
        if w == 0:
            t = max(t, bin(a).count("1"))
    return t


# --------------------------------------------------------------------------- #
# CA simulation
# --------------------------------------------------------------------------- #
def ca_step(state: Sequence[int], rule: int, boundary: str = "periodic") -> List[int]:
    n = len(state)
    table = rule_number_to_table(rule)
    out: List[int] = []
    for i in range(n):
        if boundary == "periodic":
            l = state[(i - 1) % n]
            r = state[(i + 1) % n]
        elif boundary == "null":
            l = state[i - 1] if i > 0 else 0
            r = state[i + 1] if i < n - 1 else 0
        elif boundary == "reflective":
            l = state[i - 1] if i > 0 else state[i]
            r = state[i + 1] if i < n - 1 else state[i]
        else:
            raise ValueError("boundary must be 'periodic' | 'reflective' | 'null'")
        idx = (l << 2) | (state[i] << 1) | r
        out.append(table[idx])
    return out


def ca_keystream(
    state: Sequence[int],
    rule: int,
    taps: Sequence[int],
    nbits: int,
    boundary: str = "periodic",
) -> List[int]:
    """Iterate a CA and emit the XOR of the tapped cells each step."""
    s = list(state)
    bits: List[int] = []
    for _ in range(nbits):
        bits.append(sum(s[t] for t in taps) & 1)
        s = ca_step(s, rule, boundary)
    return bits


# --------------------------------------------------------------------------- #
# Linear degeneration screen
# --------------------------------------------------------------------------- #
def screen_linear_degeneration(
    rule: int,
    n: int = 64,
    nbits: int = 4096,
    boundary: str = "periodic",
    seed: Optional[Sequence[int]] = None,
) -> dict:
    """Flag CA rules that collapse to a linear system.

    A linear (or affine) CA rule yields a keystream with linear complexity at
    most ``n`` (the cell count), i.e. ``ratio`` far below 1; such a rule is
    broken immediately by Berlekamp-Massey.
    """
    from .linear import berlekamp_massey

    if seed is None:
        seed = [1 if i == 0 else 0 for i in range(n)]
    bits = ca_keystream(seed, rule, [0], nbits, boundary)
    L, _ = berlekamp_massey(bits)
    return {
        "rule": rule,
        "linear_complexity": L,
        "nbits": nbits,
        "ratio": L / (nbits / 2.0),
        "degenerate": L <= n,
    }
