"""Keystream ingestion, bit/byte conversion, and the cipher adapter contract.

The whole toolchain is built around :class:`CipherAdapter`. Any cipher that can
emit a keystream can be analyzed as a black box; implementing the optional
structural hooks (``init``/``step``/``output_function``) unlocks structural
attacks, forward/backward security, and FPGA estimation.
"""

from __future__ import annotations

from typing import Iterable, Iterator, List, Optional, Sequence

__all__ = [
    "CipherAdapter",
    "bits_to_bytes",
    "bytes_to_bits",
    "hex_to_bits",
    "read_bits_file",
    "generate_samples",
]


class CipherAdapter:
    """Base class every cipher must subclass.

    Black-box minimum: implement :meth:`keystream`. Structural analysis: also
    implement ``init``/``step``/``output_function``.
    """

    name = "unnamed"
    key_size = 0      # bits
    iv_size = 0       # bits
    state_size = 0    # bits

    # ------------------------------------------------------------------ #
    # Black-box interface (REQUIRED)
    # ------------------------------------------------------------------ #
    def keystream(self, key: bytes, iv: bytes, nbits: int) -> List[int]:
        """Return ``nbits`` keystream bits as a list of ints in {0, 1}.

        ``key`` and ``iv`` are bytes (``iv`` may be ``b""`` if the cipher has no
        IV). The default bit order is LSB-first within each byte; override
        ``bytes_to_bits``/``bits_to_bytes`` usage if the cipher uses MSB-first.
        """
        raise NotImplementedError("subclasses must implement keystream(key, iv, nbits)")

    # ------------------------------------------------------------------ #
    # Structural interface (OPTIONAL — unlocks white-box analysis)
    # ------------------------------------------------------------------ #
    def init(self, key: bytes, iv: bytes):
        """Return the initial internal state."""
        raise NotImplementedError

    def step(self, state):
        """Advance one clock; return ``(new_state, output_bits)``."""
        raise NotImplementedError

    def output_function(self, state):
        """Return output bits produced from ``state`` (if separate from step)."""
        raise NotImplementedError

    # Optional CA metadata used by ca_model for automatic equation generation.
    rule_table = None          # e.g. dict {(l,c,r): out} for radius-1 CA
    neighborhood_radius = 1
    boundary = "periodic"      # 'periodic' | 'null' | 'reflective'


# ---------------------------------------------------------------------- #
# Bit/byte conversion (parameterized bit order; LSB-first by default)
# ---------------------------------------------------------------------- #
def bits_to_bytes(bits: Sequence[int], bitorder: str = "lsb") -> bytes:
    """Pack bits (0/1 ints) into bytes, padding the last byte with zeros."""
    bits = [int(b) & 1 for b in bits]
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j >= len(bits):
                break
            pos = j if bitorder == "lsb" else (7 - j)
            byte |= bits[i + j] << pos
        out.append(byte)
    return bytes(out)


def bytes_to_bits(data: bytes, bitorder: str = "lsb") -> List[int]:
    """Unpack bytes into a list of 0/1 bits."""
    bits: List[int] = []
    for byte in data:
        for j in range(8):
            pos = j if bitorder == "lsb" else (7 - j)
            bits.append((byte >> pos) & 1)
    return bits


def hex_to_bits(hexstr: str, bitorder: str = "lsb") -> List[int]:
    """Convert a hex string to bits (byte order = hex order)."""
    return bytes_to_bits(bytes.fromhex(hexstr.replace(" ", "").replace("\n", "")), bitorder)


# ---------------------------------------------------------------------- #
# Keystream file reading
# ---------------------------------------------------------------------- #
def read_bits_file(path: str, mode: str = "auto", bitorder: str = "lsb") -> List[int]:
    """Read a keystream file.

    Modes:
      * 'auto'  — guess from extension: .bits/.txt ascii 0/1, .hex, else binary
      * 'ascii' — whitespace-separated 0/1 characters
      * 'hex'   — hex string
      * 'bin'   — raw bytes
    """
    with open(path, "rb") as f:
        data = f.read()

    if mode == "auto":
        p = path.lower()
        if p.endswith(".hex"):
            mode = "hex"
        elif p.endswith((".bits", ".txt")):
            mode = "ascii"
        else:
            mode = "bin"

    if mode == "ascii":
        text = data.decode("ascii", errors="ignore")
        return [int(c) for c in text if c in "01"]
    if mode == "hex":
        return bytes_to_bits(bytes.fromhex(data.decode("ascii", errors="ignore")), bitorder)
    return bytes_to_bits(data, bitorder)


# ---------------------------------------------------------------------- #
# Sample generation (seeding strategies)
# ---------------------------------------------------------------------- #
def generate_samples(
    adapter: CipherAdapter,
    nseq: int,
    nbits: int,
    key: Optional[bytes] = None,
    iv_mode: str = "counter",
) -> Iterator[List[int]]:
    """Yield ``nseq`` keystreams of ``nbits`` bits.

    ``iv_mode``:
      * 'counter' — IV = big-endian counter over seq index (default)
      * 'random'  — IV = deterministic pseudo-random bytes (no external RNG)
      * 'none'    — IV = b"" (no IV cipher)

    ``key`` defaults to ``adapter.key_size//8`` zero bytes if not supplied.
    """
    if key is None:
        key = bytes(adapter.key_size // 8) if adapter.key_size else b"\x00" * 16

    for idx in range(nseq):
        if iv_mode == "counter":
            w = max(1, (adapter.iv_size + 7) // 8) if adapter.iv_size else 16
            iv = idx.to_bytes(w, "big")
        elif iv_mode == "random":
            iv = _deterministic_iv(idx, max(1, adapter.iv_size // 8 or 16))
        else:
            iv = b""
        yield adapter.keystream(key, iv, nbits)


def _deterministic_iv(idx: int, nbytes: int) -> bytes:
    """A cheap deterministic byte stream for reproducible 'random' IVs."""
    out = bytearray()
    x = (idx + 1) * 0x9E3779B97F4A7C15 & ((1 << 64) - 1)
    for _ in range(nbytes):
        x = (x * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        out.append((x >> 56) & 0xFF)
    return bytes(out)
