"""TESTU01 wrapper (SmallCrush / Crush / BigCrush / Rabbit / Alphabit).

Requires WSL + TestU01 + the compiled driver ``testu01_driver.c`` (see
``docs/environment.md``). The driver reads a TEXT file of 32-bit unsigned
decimal integers (one per line) via ``ufile_CreateReadText``.

Keystream data requirements (approximate, total bits):
  * SmallCrush: ~2^28 bits (~320 Mbit  = ~40 MB as 32-bit words)
  * Crush:      ~2^35 bits (~34  Gbit  = ~4.3 GB)
  * BigCrush:   ~2^38 bits (~274 Gbit  = ~34 GB)   -> use the cloud

The exact bit order inside each 32-bit word does not affect validity (any
consistent packing yields a uniform [0,1) stream), but ``bits_to_words`` uses
LSB-first for reproducibility.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import List, Sequence

__all__ = ["bits_to_words", "words_to_text_file", "run_testu01", "BATTERIES", "DATA_BITS"]

BATTERIES = ("smallcrush", "crush", "bigcrush", "rabbit", "alphabit")

# Approximate total keystream bits consumed by each battery.
DATA_BITS = {"smallcrush": 2 ** 28, "crush": 2 ** 35, "bigcrush": 2 ** 38,
             "rabbit": 2 ** 22, "alphabit": 2 ** 24}

# Path of the compiled driver inside WSL (see docs/environment.md).
DRIVER_PATH = "/root/testu01_driver"


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


def words_to_text_file(words: Sequence[int], path: str) -> str:
    """Write 32-bit words as decimal integers, one per line."""
    with open(path, "w") as f:
        for w in words:
            f.write(str(int(w)) + "\n")
    return path


def _win_to_wsl(path: str) -> str:
    """D:\\hardness\\... -> /mnt/d/hardness/..."""
    p = path.replace("\\", "/")
    drive, rest = p[0].lower(), p[2:]
    return f"/mnt/{drive}{rest}"


def run_testu01(bits: Sequence[int], battery: str = "smallcrush",
                workdir: str = None, timeout: int = None, driver: str = DRIVER_PATH) -> dict:
    """Convert keystream bits -> 32-bit words -> text file, then run the battery.

    Returns ``{battery, returncode, stdout, stderr, words, bits}``. Requires the
    driver compiled in WSL; callers should check ``returncode`` and the battery
    output text for p-values (TestU01 prints a summary table).
    """
    if battery not in BATTERIES:
        raise ValueError(f"battery must be one of {BATTERIES}")
    words = bits_to_words(bits)
    wdir = workdir or tempfile.mkdtemp(prefix="testu01-")
    os.makedirs(wdir, exist_ok=True)
    path = words_to_text_file(words, os.path.join(wdir, "keystream.txt"))
    wsl_path = _win_to_wsl(path)
    cmd = ["wsl", "-u", "root", "-e", driver, battery, wsl_path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {
        "battery": battery,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "words": len(words),
        "bits": len(words) * 32,
    }
