"""Algebraic attack core: GF(2) linear algebra, XL linearization, CA equations.

Solves systems of Boolean polynomial equations by **linearization** (XL): each
monomial of degree <= D becomes one linear variable, and the resulting GF(2)
linear system is solved with Gaussian elimination.  This is exact for linear
systems (D=1) and a controlled truncation for higher degree; SAT / Grobner
solvers can be wired in later (see ``security.py`` and the skill doc).

Self-contained: standard library only.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .ca_model import algebraic_degree, anf_from_table, rule_number_to_table

__all__ = ["gf2_solve", "BooleanSystem", "ca_equations", "solve_ca"]


# --------------------------------------------------------------------------- #
# GF(2) linear algebra
# --------------------------------------------------------------------------- #
def gf2_solve(A: Sequence[Sequence[int]], b: Sequence[int]) -> Dict:
    """Solve ``A x = b`` over GF(2) by Gauss-Jordan elimination.

    Returns ``{status, rank, pivots, x}`` where ``status`` is one of
    ``unique`` / ``underdetermined`` / ``inconsistent``; ``x`` is a solution
    vector with free variables set to 0 (meaningful only when consistent).
    """
    nrows = len(A)
    ncols = len(A[0]) if A else 0
    M = [list(A[i]) + [int(b[i]) & 1] for i in range(nrows)]

    row = 0
    pivots: List[int] = []
    for col in range(ncols):
        pivot = next((r for r in range(row, nrows) if M[r][col]), None)
        if pivot is None:
            continue
        M[row], M[pivot] = M[pivot], M[row]
        for r in range(nrows):
            if r != row and M[r][col]:
                for c in range(col, ncols + 1):
                    M[r][c] ^= M[row][c]
        pivots.append(col)
        row += 1
        if row == nrows:
            break

    # consistency check
    for r in range(row, nrows):
        if all(M[r][c] == 0 for c in range(ncols)) and M[r][ncols] == 1:
            return {"status": "inconsistent", "rank": row, "pivots": pivots, "x": None}

    x = [0] * ncols
    for r, col in enumerate(pivots):
        x[col] = M[r][ncols]
    status = "unique" if len(pivots) == ncols else "underdetermined"

    # Uniquely determined columns: pivot columns whose row has no free-column
    # entries (their value does not depend on any free variable).
    free = set(range(ncols)) - set(pivots)
    determined = {}
    for r, col in enumerate(pivots):
        if all(M[r][c] == 0 for c in free):
            determined[col] = M[r][ncols]

    return {"status": status, "rank": row, "pivots": pivots, "x": x, "determined": determined}


# --------------------------------------------------------------------------- #
# Boolean polynomial system (linearization / XL)
# --------------------------------------------------------------------------- #
class BooleanSystem:
    """A system of Boolean polynomial equations (each polynomial = 0 over GF(2)).

    A monomial is a ``frozenset`` of variable ids; the empty frozenset is the
    constant term.
    """

    def __init__(self) -> None:
        self._names: List = []
        self._id: Dict = {}
        self.eqs: List[Dict[frozenset, int]] = []

    def add_var(self, name) -> int:
        if name not in self._id:
            self._id[name] = len(self._names)
            self._names.append(name)
        return self._id[name]

    def var(self, name) -> int:
        return self._id[name]

    def add_equation(self, monomials) -> None:
        """``monomials``: dict {frozenset(var ids): coeff} or iterable of (monomial, coeff)."""
        d: Dict[frozenset, int] = {}
        items = monomials.items() if isinstance(monomials, dict) else monomials
        for m, c in items:
            fm = frozenset(m)
            d[fm] = d.get(fm, 0) ^ (int(c) & 1)
        self.eqs.append({m: c for m, c in d.items() if c})

    def linearize(self, max_degree: int):
        """Build the GF(2) linear system over monomials of degree <= ``max_degree``.

        Returns ``(A, b, cols, col_of)``; monomials of higher degree are dropped
        (the XL truncation).
        """
        all_mono: Set[frozenset] = set()
        for eq in self.eqs:
            for m, c in eq.items():
                if c and m and len(m) <= max_degree:
                    all_mono.add(m)
        cols = sorted(all_mono, key=lambda m: (len(m), sorted(m)))
        col_of = {m: i for i, m in enumerate(cols)}
        A = [[0] * len(cols) for _ in self.eqs]
        b = [0] * len(self.eqs)
        for ei, eq in enumerate(self.eqs):
            for m, c in eq.items():
                if not m:
                    b[ei] ^= c
                elif len(m) <= max_degree:
                    A[ei][col_of[m]] ^= c
        return A, b, cols, col_of

    def solve(self, max_degree: int) -> Dict:
        A, b, cols, col_of = self.linearize(max_degree)
        res = gf2_solve(A, b)
        res.update({"cols": cols, "col_of": col_of, "ncols": len(cols), "neqs": len(self.eqs)})
        return res


# --------------------------------------------------------------------------- #
# CA equation generation
# --------------------------------------------------------------------------- #
def ca_equations(
    rule: int,
    n: int,
    steps: int,
    taps: Sequence[int],
    observed_bits: Sequence[int],
    boundary: str = "periodic",
) -> BooleanSystem:
    """Build the GF(2) equation system of a radius-1 elementary CA.

    Variables are ``(t, i)`` = cell ``i`` at time ``t``. Equations encode the
    local rule ``x[t+1][i] = f(x[t][i-1], x[t][i], x[t][i+1])`` and the output
    ``y[t] = XOR of tapped cells``, with ``y[t]`` set to ``observed_bits[t]``.
    """
    sys = BooleanSystem()
    for t in range(steps + 1):
        for i in range(n):
            sys.add_var((t, i))

    anf = anf_from_table(rule_number_to_table(rule))
    sys.rule_degree = algebraic_degree(anf)
    for t in range(steps):
        for i in range(n):
            if boundary == "periodic":
                l = (i - 1) % n
                r = (i + 1) % n
            elif boundary == "null":
                l = i - 1 if i > 0 else 0
                r = i + 1 if i < n - 1 else n - 1
            else:
                raise ValueError("boundary must be 'periodic' | 'null'")
            terms: Dict[frozenset, int] = {frozenset([sys.var((t + 1, i))]): 1}
            for idx, c in enumerate(anf):
                if c:
                    m = set()
                    if idx & 1:   # x0 -> right neighbor
                        m.add(sys.var((t, r)))
                    if idx & 2:   # x1 -> center
                        m.add(sys.var((t, i)))
                    if idx & 4:   # x2 -> left neighbor
                        m.add(sys.var((t, l)))
                    terms[frozenset(m)] = 1
            sys.add_equation(terms)

    for t in range(steps):
        terms = {frozenset([sys.var((t, tap))]): 1 for tap in taps}
        terms[frozenset()] = int(observed_bits[t]) & 1 if t < len(observed_bits) else 0
        sys.add_equation(terms)

    return sys


def solve_ca(rule: int, n: int, steps: int, taps: Sequence[int],
             observed_bits: Sequence[int], max_degree: int = 1, boundary: str = "periodic") -> Dict:
    """Convenience: build the CA system and solve for the initial state cells."""
    sys = ca_equations(rule, n, steps, taps, observed_bits, boundary)
    res = sys.solve(max_degree)
    det = res.get("determined", {})
    init = {}
    for i in range(n):
        m = frozenset([sys.var((0, i))])
        col = res["col_of"].get(m)
        init[i] = det.get(col) if col is not None else None
    res["initial_state"] = init
    res["determined_count"] = sum(1 for v in init.values() if v is not None)
    res["rule_degree"] = getattr(sys, "rule_degree", None)
    return res
