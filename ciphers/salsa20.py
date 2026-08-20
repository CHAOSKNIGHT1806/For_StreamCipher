"""Salsa20 stream cipher (Bernstein).

256-bit key, 64-bit nonce, 20 rounds.  Pure-Python reference implementation
following the Salsa20 specification (expands a 16-word input, adds back, emits
512-bit blocks).  Uses Bernstein's canonical little-endian word byte packing.

Bit order: Salsa20 produces keystream bytes; we unpack LSB-first per
``ingest.bytes_to_bits`` (the toolchain's default), so bit 0 of output is the
LSB of the first keystream byte.
"""
from __future__ import annotations

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ingest import CipherAdapter, bytes_to_bits


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _quarterround(a, b, c, d, y, off):
    # Salsa20 quarterround on y[a], y[b], y[c], y[d]:
    #   b ^= rotl(a + d, 7); c ^= rotl(b + a, 9);
    #   d ^= rotl(c + b, 13); a ^= rotl(d + c, 18)
    ya = y[a]; yb = y[b]; yc = y[c]; yd = y[d]

    yb ^= _rotl((ya + yd) & 0xFFFFFFFF, 7)
    yc ^= _rotl((yb + ya) & 0xFFFFFFFF, 9)
    yd ^= _rotl((yc + yb) & 0xFFFFFFFF, 13)
    ya ^= _rotl((yd + yc) & 0xFFFFFFFF, 18)

    y[a] = ya & 0xFFFFFFFF
    y[b] = yb & 0xFFFFFFFF
    y[c] = yc & 0xFFFFFFFF
    y[d] = yd & 0xFFFFFFFF


def _salsa20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    # Constants "expand 32-byte k"
    c = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

    def le32(b: bytes, off: int) -> int:
        return int.from_bytes(b[off:off + 4], "little")

    k0, k1, k2, k3 = le32(key, 0), le32(key, 4), le32(key, 8), le32(key, 12)
    k4, k5, k6, k7 = le32(key, 16), le32(key, 20), le32(key, 24), le32(key, 28)
    n0, n1 = le32(nonce, 0), le32(nonce, 4)
    ctr = counter & 0xFFFFFFFF
    b0, b1 = ctr & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF

    x = [c[0], k0, k1, k2,
         k3, c[1], n0, n1,
         b0, b1, c[2], k4,
         k5, k6, k7, c[3]]
    y = list(x)

    for _ in range(10):  # 10 double rounds = 20 rounds
        # column round
        _quarterround(0, 4, 8, 12, y, 0)
        _quarterround(5, 9, 13, 1, y, 0)
        _quarterround(10, 14, 2, 6, y, 0)
        _quarterround(15, 3, 7, 11, y, 0)
        # row round
        _quarterround(0, 1, 2, 3, y, 0)
        _quarterround(5, 6, 7, 4, y, 0)
        _quarterround(10, 11, 8, 9, y, 0)
        _quarterround(15, 12, 13, 14, y, 0)

    out = bytearray(64)
    for i in range(16):
        w = (y[i] + x[i]) & 0xFFFFFFFF
        out[4 * i:4 * i + 4] = w.to_bytes(4, "little")
    return bytes(out)


class Salsa20(CipherAdapter):
    name = "Salsa20"
    key_size = 256   # bits
    iv_size = 64     # bits (8-byte nonce)

    def keystream(self, key: bytes, iv: bytes, nbits: int) -> List[int]:
        key = key[:32].ljust(32, b"\x00")
        nonce = iv[:8].ljust(8, b"\x00")
        nbytes = (nbits + 7) // 8
        ks = bytearray()
        counter = 0
        while len(ks) < nbytes:
            ks += _salsa20_block(key, nonce, counter)
            counter += 1
        return bytes_to_bits(bytes(ks), "lsb")[:nbits]


if __name__ == "__main__":
    # Bernstein's Salsa20 spec test vector (set 0), cross-checked against
    # pycryptodome: key = 0x80 || 0x00*31, nonce = 0, first 8 keystream bytes
    # = e3 be 8f dd 8b ec a2 e3.
    key = b"\x80" + b"\x00" * 31
    ks = Salsa20().keystream(key, b"\x00" * 8, 64)
    from analyzer.ingest import bits_to_bytes
    hexval = bits_to_bytes(ks, "lsb").hex()
    expected = "e3be8fdd8beca2e3"
    if hexval == expected:
        print(f"OK: Salsa20 matches test vector (first 8 keystream bytes = {hexval})")
    else:
        print(f"FAIL: Salsa20 got {hexval}, expected {expected}")
