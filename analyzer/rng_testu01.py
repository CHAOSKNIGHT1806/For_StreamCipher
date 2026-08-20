"""TESTU01 wrapper (SmallCrush / Crush / BigCrush) — needs WSL + compiled TestU01.

The classic TestU01 battery binaries read a stream of 32-bit unsigned integers.
This module converts a bit keystream to 32-bit words and shells out to the
battery via ``wsl``.

.. note::
   NOT YET VERIFIED end-to-end: requires TestU01 compiled under WSL (see
   ``docs/environment.md``). The exact battery CLI (binary vs decimal stdin) is
   confirmed at first run after WSL is installed.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from typing import List, Sequence

__all__ = ["bits_to_words", "run_testu01", "BATTERIES"]

BATTERIES = ("smallcrush", "crush", "bigcrush")


def bits_to_words(bits: Sequence[int], bitorder: str = "lsb", word_bits: int = 32) -> List[int]:
    """Pack bits into 32-bit unsigned words (LSB-first within a word by default)."""
    words: List[int] = []
    for i in range(0, len(bits) - word_bits + 1, word_bits):
        w = 0
        for j in range(word_bits):
            pos = j if bitorder == "lsb" else (word_bits - 1 - j)
            w |= (int(bits[i + j]) & 1) << pos
        words.append(w)
    return words


def _win_to_wsl(path: str) -> str:
    """D:\\hardness\\... -> /mnt/d/hardness/..."""
    p = path.replace("\\", "/")
    drive, rest = p[0].lower(), p[2:]
    return f"/mnt/{drive}{rest}"


def run_testu01(bits: Sequence[int], battery: str = "bigcrush",
                workdir: str = None, timeout: int = None) -> dict:
    """Run a TestU01 battery over the keystream bits; returns raw output.

    Raises ``RuntimeError`` if ``wsl`` is unavailable. The battery invocation
    itself is finalized after TestU01 is installed (documented TODO).
    """
    if battery not in BATTERIES:
        raise ValueError(f"battery must be one of {BATTERIES}")
    if subprocess.run(["wsl", "--status"], capture_output=True).returncode != 0:
        raise RuntimeError("WSL not available; install TestU01 first (docs/environment.md)")

    words = bits_to_words(bits)
    wdir = workdir or tempfile.mkdtemp(prefix="testu01-")
    os.makedirs(wdir, exist_ok=True)
    path = os.path.join(wdir, "keystream.bin")
    with open(path, "wb") as f:
        for w in words:
            f.write(struct.pack("<I", w))

    wsl_path = _win_to_wsl(path)
    # TODO(verify): confirm stdin format of the TestU01 battery binaries.
    cmd = ["wsl", "bash", "-lc", f"{battery} < {wsl_path}"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {
        "battery": battery,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "words": len(words),
    }
