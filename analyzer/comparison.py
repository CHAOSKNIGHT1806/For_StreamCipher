"""Reference-cipher comparison data and CA attack-surface catalog.

Structured from the literature scan (``docs/literature-scan.md``). Every entry
carries a citation; do not fabricate numbers. ``comparison_table`` emits a
paper-ready LaTeX + CSV table.
"""

from __future__ import annotations

from typing import List, Sequence

from .report import csv_table, latex_table

__all__ = ["REFERENCE_CIPHERS", "CA_ATTACK_SURFACE", "comparison_table", "ca_attack_surface_table"]

# --------------------------------------------------------------------------- #
# Reference ciphers (for the comparison table)
# --------------------------------------------------------------------------- #
REFERENCE_CIPHERS: List[dict] = [
    {
        "cipher": "ChaCha20", "type": "ARX",
        "key_iv": "256 / 96", "state_bits": 512, "claimed_bits": 256,
        "best_attack": "reduced-round only (7-round)",
        "status": "secure",
        "ref": "Aumasson et al., FSE 2008, ePrint 2007/472; RFC 8439",
    },
    {
        "cipher": "Trivium", "type": "NFSR",
        "key_iv": "80 / 80", "state_bits": 288, "claimed_bits": 80,
        "best_attack": "805-round key-recovery",
        "status": "secure",
        "ref": "Ye et al., ASIACRYPT 2021",
    },
    {
        "cipher": "Grain-128AEAD", "type": "NFSR+LFSR",
        "key_iv": "128 / 96", "state_bits": 256, "claimed_bits": 128,
        "best_attack": "dynamic cube on v1 (FSE 2011); AEAD unbroken",
        "status": "secure",
        "ref": "Dinur et al., FSE 2011, doi:10.1007/978-3-642-21702-9_10",
    },
    {
        "cipher": "ZUC-256", "type": "LFSR+NL",
        "key_iv": "256 / 184", "state_bits": "16x31 LFSR", "claimed_bits": 256,
        "best_attack": "init-phase differential",
        "status": "secure",
        "ref": "Babbage-Maximov, ePrint 2020/1215; ePrint 2021/1104",
    },
    {
        "cipher": "SNOW 3G", "type": "LFSR+FSM",
        "key_iv": "128 / 128", "state_bits": 512, "claimed_bits": 128,
        "best_attack": "fast correlation (~2^-40.97)",
        "status": "secure",
        "ref": "ETSI TS 135 216; ePrint 2019/991",
    },
    {
        "cipher": "HC-128", "type": "table-based",
        "key_iv": "128 / 128", "state_bits": "2x512x32", "claimed_bits": 128,
        "best_attack": "distinguishers / partial recovery",
        "status": "secure",
        "ref": "Wu, FSE 2008; Stankovski et al., Zbl 1236.94067",
    },
    {
        "cipher": "Rabbit", "type": "counter+NL",
        "key_iv": "128 / 64", "state_bits": 513, "claimed_bits": 128,
        "best_attack": "none known (full round)",
        "status": "secure",
        "ref": "RFC 4503",
    },
    {
        "cipher": "Salsa20/12", "type": "ARX",
        "key_iv": "256 / 64", "state_bits": 512, "claimed_bits": 256,
        "best_attack": "reduced-round (FSE 2008; ePrint 2015/698)",
        "status": "secure",
        "ref": "Aumasson et al., FSE 2008, ePrint 2007/472",
    },
    {
        "cipher": "RC4", "type": "KSA+PRGA",
        "key_iv": "var (typ 128) / none", "state_bits": "258x8", "claimed_bits": "~128 (historical)",
        "best_attack": "practical plaintext recovery",
        "status": "BROKEN",
        "ref": "AlFardan et al., USENIX Security 2013; RFC 7465",
    },
    {
        "cipher": "A5/1", "type": "3xLFSR",
        "key_iv": "64 (eff 54) / 22", "state_bits": 64, "claimed_bits": "64 (eff 54)",
        "best_attack": "real-time recovery (BSW)",
        "status": "BROKEN",
        "ref": "Biryukov-Shamir-Wagner, FSE 2000, doi:10.1007/3-540-44706-7_1",
    },
]

# --------------------------------------------------------------------------- #
# CA attack-surface catalog (for Related Work + Tier-2 argument)
# --------------------------------------------------------------------------- #
CA_ATTACK_SURFACE: List[dict] = [
    {"attack": "linear rule degeneration / permutivity", "consequence": "correlation-immunity failure",
     "ref": "Meier-Staffelbach, EUROCRYPT 1991, doi:10.1007/3-540-46416-6_17"},
    {"attack": "low nonlinearity", "consequence": "best-affine-approximation attack",
     "ref": "Koc-Apohan, 1997 (per Mariot 2024, arXiv:2405.02875)"},
    {"attack": "tap / center-cell sampling leakage", "consequence": "neighbor correlation persists",
     "ref": "Mariot 2024; Spencer 2013, arXiv:1306.3546"},
    {"attack": "periodic boundary condition", "consequence": "state collapse / non-invertibility",
     "ref": "Wolfram 1985; Mariot 2024"},
    {"attack": "low algebraic degree / immunity", "consequence": "Berlekamp-Massey / Ronjom-Helleseth algebraic attacks",
     "ref": "Mariot 2024, arXiv:2405.02875"},
    {"attack": "relying on statistical/chaos tests as security", "consequence": "necessary but not sufficient",
     "ref": "Mariot 2024"},
    {"attack": "poor diffusion", "consequence": "slow differential propagation",
     "ref": "Mariot 2024"},
    {"attack": "fault injection", "consequence": "FIA against CA stream cipher",
     "ref": "Carrijo-Nascimento (Semantic Scholar)"},
    {"attack": "asynchronous-update instability", "consequence": "properties must be re-verified",
     "ref": "Mariot 2024 (Manzoni 2018)"},
]


def comparison_table(outdir: str = "results", name: str = "comparison") -> List[List[str]]:
    headers = ["Cipher", "Type", "Key/IV (bits)", "State (bits)", "Claimed (bits)",
               "Best known attack", "Status"]
    rows = [
        [e["cipher"], e["type"], e["key_iv"], str(e["state_bits"]), str(e["claimed_bits"]),
         e["best_attack"], e["status"]]
        for e in REFERENCE_CIPHERS
    ]
    csv_table(headers, rows, outdir, name)
    latex_table(headers, rows, outdir, name,
                caption="Reference stream ciphers: parameters and best known attacks.",
                label="tab:reference")
    return rows


def ca_attack_surface_table(outdir: str = "results", name: str = "ca_attack_surface") -> List[List[str]]:
    headers = ["Attack", "Consequence", "Reference"]
    rows = [[e["attack"], e["consequence"], e["ref"]] for e in CA_ATTACK_SURFACE]
    csv_table(headers, rows, outdir, name)
    latex_table(headers, rows, outdir, name,
                caption="Known attack surface of cellular-automaton stream ciphers.",
                label="tab:ca_attacks")
    return rows
