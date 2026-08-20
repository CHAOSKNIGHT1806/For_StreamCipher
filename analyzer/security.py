"""Forward/backward security, provable-security scaffolding, post-quantum (Grover).

Honest division of labor:
  * **Tier 1** (reduction to a hard problem) is only claimed when the design
    embeds such a problem; the tool provides templates, not proofs.
  * **Tier 2** (rigorous security argument + cryptanalysis, eSTREAM methodology)
    is the realistic default for heuristic CA/LFSR/NFSR designs.
"""

from __future__ import annotations

from itertools import product
from typing import Dict, List, Optional, Sequence

from .ca_model import ca_step

__all__ = [
    "ca_is_bijective",
    "permutive_rules",
    "grover_security_bits",
    "quantum_security_table",
    "provable_security_checklist",
    "forward_backward_summary",
]

# Elementary CA rules that are permutive (bijective for every cell count n).
_PERMUTIVE = {15, 51, 85, 170, 204, 240}


def permutive_rules() -> set:
    return set(_PERMUTIVE)


def ca_is_bijective(rule: int, n: int, boundary: str = "periodic") -> Optional[bool]:
    """Exhaustive bijectivity check of the global CA map (small n only, n <= 16)."""
    if n > 16:
        return None
    seen = set()
    for state in product((0, 1), repeat=n):
        ns = tuple(ca_step(state, rule, boundary))
        if ns in seen:
            return False
        seen.add(ns)
    return True


def grover_security_bits(key_bits: int) -> float:
    """Grover halves the exponent: classical 2^k -> quantum ~2^(k/2)."""
    return key_bits / 2.0


def quantum_security_table(key_sizes: Sequence[int]) -> List[Dict]:
    return [
        {"key_bits": k, "classical_bits": k, "post_quantum_bits": grover_security_bits(k)}
        for k in key_sizes
    ]


def provable_security_checklist(construction_type: str) -> Dict:
    """Structured template for the provable-security section of the report."""
    templates = {
        "prf": {
            "label": "PRF/PRP-based stream cipher",
            "route": "Tier 1 possible: keystream is pseudorandom if the block cipher is a PRP/PRF (e.g. CTR mode).",
            "assumptions": ["block cipher is a PRP/PRF"],
            "theorems": ["PRF -> pseudorandom keystream (standard reduction)",
                         "Yao: next-bit unpredictability <=> pseudorandomness"],
            "to_prove": ["state the PRP/PRF assumption precisely", "give the reduction and its tightness"],
        },
        "number_theory": {
            "label": "Number-theoretic generator (e.g. BBS)",
            "route": "Tier 1 possible: reduce to quadratic residuosity / discrete log / factoring.",
            "assumptions": ["quadratic residuosity (BBS)", "or discrete log / factoring"],
            "theorems": ["BBS security <= QR assumption", "Goldreich-Levin hardcore predicate"],
            "to_prove": ["map next-bit prediction to the hard problem"],
        },
        "lattice": {
            "label": "Lattice-based PRG (LWE/LPN)",
            "route": "Tier 1 possible: reduce to LWE/LPN hardness; post-quantum candidates.",
            "assumptions": ["LWE or LPN"],
            "theorems": ["LWE/LPN -> PRG constructions"],
            "to_prove": ["reduction + parameter selection for the target security level"],
        },
        "heuristic": {
            "label": "Heuristic design (CA/LFSR/NFSR; no hardness assumption)",
            "route": "Tier 2 only: rigorous security argument + extensive cryptanalysis (eSTREAM methodology).",
            "assumptions": ["no reduction to a hard problem is claimed"],
            "theorems": ["none available"],
            "to_prove": [
                "state the claims as PRG definitions: next-bit unpredictability, state recovery hardness, forward secrecy",
                "map each attack class (algebraic/cube/correlation/distinguishing) to design features + experimental resistance",
                "list open problems honestly (do not overclaim)",
            ],
        },
    }
    return templates.get(construction_type, templates["heuristic"])


def forward_backward_summary(
    rule: Optional[int] = None,
    n: Optional[int] = None,
    key_bits: Optional[int] = None,
    construction_type: str = "heuristic",
    boundary: str = "periodic",
) -> Dict:
    """Assemble the forward/backward + provable + post-quantum summary for a CA."""
    out: Dict = {"construction_type": construction_type}
    if rule is not None and n is not None:
        bijective = ca_is_bijective(rule, n, boundary)
        if bijective is None and rule in _PERMUTIVE:
            bijective = True
        out["state_update_bijective"] = bijective
        if bijective is True:
            out["backward_security_note"] = (
                "state update is a bijection -> NOT backward-secure: a future state "
                "reveals past states (invertible)."
            )
        elif bijective is False:
            out["backward_security_note"] = (
                "state update is not a bijection; backward security depends on its "
                "one-wayness (analyze entropy loss / preimage structure further)."
            )
        else:
            out["backward_security_note"] = (
                "bijectivity not checked (n > 16); provide analysis or reduce n."
            )
    if key_bits is not None:
        pq = grover_security_bits(key_bits)
        out["post_quantum_bits"] = pq
        out["pq_note"] = f"{key_bits}-bit key -> ~{pq:.0f}-bit post-quantum security (Grover); use >=256-bit for 128-bit PQ level."
    out["provable_checklist"] = provable_security_checklist(construction_type)
    return out
