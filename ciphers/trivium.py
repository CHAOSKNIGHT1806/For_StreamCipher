"""Trivium stream cipher (eSTREAM hardware portfolio, De Canniere & Preneel).

80-bit key, 80-bit IV, 288-bit internal state. Reference implementation with
loading / initialization / keystream conventions exactly as in the eSTREAM
final specification.

Bit order: ``ingest.bytes_to_bits`` is LSB-first per byte.  eSTREAM numbers key
bits k0..k79 and IV bits v0..v79 with k0/v0 the least-significant bit of the
first byte, so LSB-first unpacking is the correct convention.
"""
from __future__ import annotations

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ingest import CipherAdapter, bytes_to_bits


class Trivium(CipherAdapter):
    name = "Trivium"
    key_size = 80      # bits
    iv_size = 80       # bits
    state_size = 288   # bits

    def keystream(self, key: bytes, iv: bytes, nbits: int) -> List[int]:
        key = key[:10].ljust(10, b"\x00")
        iv = iv[:10].ljust(10, b"\x00")
        k = bytes_to_bits(key, "lsb")   # k0..k79
        v = bytes_to_bits(iv, "lsb")    # v0..v79

        # s[i] for i in 1..288 (index 0 unused), matching spec state numbering
        # s1..s288.  Left-most register cell is s1 (shifted out first in register 1).
        s = [0] * 289

        # Load: s1..s80 = key, s81..s93 = 0, s94..s173 = IV, s174..s285 = 0,
        #       s286..s288 = 1
        for i in range(1, 81):
            s[i] = k[i - 1]
        for i in range(94, 174):
            s[i] = v[i - 94]
        s[286] = s[287] = s[288] = 1

        def clock():
            t1 = s[66] ^ s[93]
            t2 = s[162] ^ s[177]
            t3 = s[243] ^ s[288]
            z = t1 ^ t2 ^ t3
            t1 ^= s[91] & s[92]
            t2 ^= s[175] & s[176]
            t3 ^= s[286] & s[287]
            t1 ^= s[171]
            t2 ^= s[264]
            t3 ^= s[69]
            return z, t1, t2, t3

        out: List[int] = []
        for cycle in range(4 * 288 + nbits):
            z, t1, t2, t3 = clock()
            # Shift: new bit enters at the *right* end of each register; the
            # register contents shift toward lower indices.  Spec: s1..s93 = (t3,
            # s1..s92), i.e. s1' = t3 and s93' = s92.
            s[1:94] = [t3] + s[1:93]
            s[94:178] = [t1] + s[94:177]
            s[178:289] = [t2] + s[178:288]
            if cycle >= 4 * 288:
                out.append(z)

        return out


if __name__ == "__main__":
    # eSTREAM final-package test vector: all-zero key and IV.
    # First 32 keystream bits = 0xfbe0bf26 (i.e. bits: 11111011111000001011111100100110).
    ks = Trivium().keystream(b"\x00" * 10, b"\x00" * 10, 32)
    from analyzer.ingest import bits_to_bytes
    hexval = bits_to_bytes(ks, "lsb").hex()
    expected = "fbe0bf26"
    if hexval == expected:
        print(f"OK: Trivium matches test vector (first 4 keystream bytes = {hexval})")
    else:
        print(f"FAIL: Trivium got {hexval}, expected {expected}")
