"""Cube attack framework (Dinur--Shamir) over GF(2).

The cube sum over a set of ``k`` variables of an output polynomial equals the
sum of exactly those monomials that contain every cube variable, with the cube
variables removed.  This module provides both the symbolic (ANF) and black-box
(evaluator) views: superpoly evaluation, linearity testing (BLR), and recovery
of a linear superpoly (a "maxterm").
"""

from __future__ import annotations

import random
from itertools import product
from typing import Callable, Dict, List, Sequence

__all__ = [
    "superpoly_from_anf",
    "superpoly_eval",
    "test_linear_superpoly",
    "recover_linear_superpoly",
]


def superpoly_from_anf(monomials: Sequence[int], cube: Sequence[int]) -> List[int]:
    """Symbolic superpoly from an ANF given as a list of monomial bitmasks.

    ``monomials``: each int has bit ``i`` set iff variable ``i`` appears.
    ``cube``: indices of cube variables. Returns monomials (bitmasks) over the
    non-cube variables only.
    """
    cube_mask = 0
    for i in cube:
        cube_mask |= 1 << i
    out: List[int] = []
    for m in monomials:
        if (m & cube_mask) == cube_mask:
            out.append(m & ~cube_mask)
    return out


def superpoly_eval(
    f: Callable[[List[int]], int],
    cube: Sequence[int],
    nvars: int,
    assignment: Dict[int, int],
) -> int:
    """Evaluate the superpoly of ``f`` at ``assignment`` (non-cube vars only).

    ``f`` maps a length-``nvars`` bit list to a bit. Cost: 2^len(cube) calls.
    """
    k = len(cube)
    base = [0] * nvars
    for idx, b in assignment.items():
        base[idx] = int(b) & 1
    total = 0
    for combo in product((0, 1), repeat=k):
        bits = base[:]
        for ci, b in zip(cube, combo):
            bits[ci] = b
        total ^= int(f(bits)) & 1
    return total


def _noncube(nvars: int, cube: Sequence[int]) -> List[int]:
    cset = set(cube)
    return [i for i in range(nvars) if i not in cset]


def test_linear_superpoly(
    f: Callable[[List[int]], int],
    cube: Sequence[int],
    nvars: int,
    trials: int = 16,
) -> bool:
    """BLR-style test whether the superpoly is affine (degree <= 1)."""
    noncube = _noncube(nvars, cube)
    zero = {i: 0 for i in noncube}
    f0 = superpoly_eval(f, cube, nvars, zero)
    for _ in range(trials):
        a = {i: random.getrandbits(1) for i in noncube}
        b = {i: random.getrandbits(1) for i in noncube}
        axb = {i: a[i] ^ b[i] for i in noncube}
        fa = superpoly_eval(f, cube, nvars, a)
        fb = superpoly_eval(f, cube, nvars, b)
        fab = superpoly_eval(f, cube, nvars, axb)
        if fab != (fa ^ fb ^ f0):
            return False
    return True


def recover_linear_superpoly(
    f: Callable[[List[int]], int],
    cube: Sequence[int],
    nvars: int,
) -> Dict:
    """Assume the superpoly is linear; recover constant term + coefficients."""
    noncube = _noncube(nvars, cube)
    zero = {i: 0 for i in noncube}
    const = superpoly_eval(f, cube, nvars, zero)
    coeffs: Dict[int, int] = {}
    for i in noncube:
        one = {j: 0 for j in noncube}
        one[i] = 1
        coeffs[i] = superpoly_eval(f, cube, nvars, one) ^ const
    return {"cube": list(cube), "constant": const, "coefficients": coeffs}
