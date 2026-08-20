"""Performance estimation: fixed-clock FPGA model + software benchmark scaffold.

FPGA numbers are a *rough* model (1 LUT + 1 FF per cell per clock, critical
path = one combinational level) normalized to a single fixed clock for
cross-cipher comparison; real synthesis data can be fed in later.
"""

from __future__ import annotations

import shutil
from typing import Dict, List, Optional, Sequence

__all__ = ["throughput_mbps", "ca_fpga_estimate", "software_benchmark", "comparison_rows"]


def throughput_mbps(output_bits_per_cycle: float, freq_mhz: float) -> float:
    """Throughput in Mbit/s = output_bits/cycle * clock(MHz)."""
    return output_bits_per_cycle * freq_mhz


def ca_fpga_estimate(
    n_cells: int,
    output_bits_per_cycle: int,
    freq_mhz: float = 100.0,
    lut_per_cell: int = 1,
    ff_per_cell: int = 1,
) -> Dict:
    """Rough FPGA estimate for an iterative elementary-CA core (fully parallel).

    Assumes one 3-input LUT + one FF per cell per clock; critical path is one
    combinational level (a single radius-1 CA update). This is a normalized
    model, not a synthesis result.
    """
    return {
        "clock_mhz": freq_mhz,
        "cells": n_cells,
        "luts": n_cells * lut_per_cell,
        "ffs": n_cells * ff_per_cell,
        "critical_path": "1 LUT level (assumed)",
        "output_bits_per_cycle": output_bits_per_cycle,
        "throughput_mbps": throughput_mbps(output_bits_per_cycle, freq_mhz),
        "note": "rough model: 1 LUT + 1 FF per cell; real synthesis will differ",
    }


def software_benchmark(c_source_path: Optional[str] = None, nbytes: int = 1 << 30) -> Dict:
    """Software throughput benchmark — requires a C toolchain (WSL + gcc).

    Does not fabricate numbers: returns a pending marker and instructions until
    the C reference is compiled and timed.
    """
    have_cc = shutil.which("gcc") is not None or shutil.which("clang") is not None
    have_wsl = shutil.which("wsl") is not None
    if not (have_cc or have_wsl):
        return {
            "status": "unavailable",
            "note": "no C compiler; install WSL + gcc (see docs/environment.md) to benchmark software throughput.",
        }
    return {
        "status": "pending",
        "note": "compile the cipher reference to C and time it at -O3; report MB/s and cycles/byte.",
        "nbytes": nbytes,
        "compiler": "gcc" if have_cc else "wsl gcc",
    }


def comparison_rows(entries: Sequence[Dict]) -> tuple:
    """Flatten a list of per-cipher dicts into (headers, rows) for a table."""
    headers = sorted({k for e in entries for k in e})
    rows = [[e.get(h, "") for h in headers] for e in entries]
    return headers, rows
