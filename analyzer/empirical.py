"""Empirical black-box comparison across registered reference ciphers.

Complements the literature-backed ``comparison.py`` table with *measured*
black-box properties (linear complexity, monobit, runs) computed by this tool.
"""

from __future__ import annotations

from typing import List

from .linear import linear_complexity
from .stats import monobit, runs_test

__all__ = ["empirical_row", "empirical_comparison"]


def empirical_row(adapter, nbits: int = 20000, lc_bits: int = 2048) -> dict:
    key = bytes(adapter.key_size // 8 or 16)
    iv = bytes(adapter.iv_size // 8 or 0)
    seq = adapter.keystream(key, iv, nbits)
    mb = monobit(seq)
    rn = runs_test(seq)
    lc = linear_complexity(seq[:lc_bits])
    return {
        "cipher": adapter.name,
        "linear_complexity": lc,
        "monobit_z": round(mb["z"], 3),
        "runs_z": round(rn["z"], 3),
        "prop_ones": round(mb["prop_ones"], 4),
    }


def empirical_comparison(adapters, nbits: int = 20000, lc_bits: int = 2048) -> List[dict]:
    return [empirical_row(a, nbits, lc_bits) for a in adapters]
