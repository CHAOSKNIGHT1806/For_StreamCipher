"""A5/1 stream cipher (GSM over-the-air).

64-bit key (Kc), 22-bit frame number (IV/frame).  Three LFSRs of lengths 19, 22,
23 with majority-clock rule.  Reference implementation following the published
A5/1 description.

Conventions: key bits are loaded LSB-first per byte (Kc bit 0 = LSB of byte 0,
matching ``ingest.bytes_to_bits``).  The 22-bit frame number is taken from the
IV bytes LSB-first, and each frame bit is XORed into the LSB-tap feedback of all
three registers during loading.  Function F() (the "irregular clocking combined
output" used around GSM handover) is NOT part of the standard keystream and is
omitted; we emit the standard per-clock output bit.
"""
from __future__ import annotations

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ingest import CipherAdapter, bytes_to_bits

# Tap positions (0-indexed bit positions counting from LSB / the shift-in end).
# Feedback polynomials (from GSM spec, bit numbering: output taken from bit 0):
#   R1: x^19 + x^18 + x^17 + x^14 + 1  -> tap bits 13, 16, 17, 18
#   R2: x^22 + x^21 + 1                -> tap bit 20, 21
#   R3: x^23 + x^22 + x^21 + x^8 + 1   -> tap bits 7, 20, 21, 22
_R1_LEN, _R1_TAPS = 19, (13, 16, 17, 18)
_R2_LEN, _R2_TAPS = 22, (20, 21)
_R3_LEN, _R3_TAPS = 23, (7, 20, 21, 22)


def _feedback(reg: int, len_: int, taps) -> int:
    """Parity of tapped bits (XOR), returned as the new input bit."""
    par = 0
    for t in taps:  # t is the bit index counting from bit 0 = LSB/oldest
        par ^= (reg >> t) & 1
    return par


def _clock_register(reg: int, len_: int, taps, fb: int) -> int:
    """Shift right (toward lower bit index) and insert ``fb`` at the top bit."""
    reg >>= 1
    reg |= (fb & 1) << (len_ - 1)
    return reg & ((1 << len_) - 1)


class A51(CipherAdapter):
    name = "A5/1"
    key_size = 64    # bits
    iv_size = 22     # bits (frame number)
    state_size = 64  # bits (19+22+23)

    def keystream(self, key: bytes, iv: bytes, nbits: int) -> List[int]:
        key = key[:8].ljust(8, b"\x00")
        iv = iv[:3].ljust(3, b"\x00")
        k = bytes_to_bits(key, "lsb")     # 64 key bits
        f = bytes_to_bits(iv, "lsb")[:22]  # 22 frame bits
        return self._run(k, f, nbits)

    def _run(self, k: List[int], f: List[int], nbits: int) -> List[int]:
        r1 = r2 = r3 = 0
        for i in range(64):
            fb = k[i]
            r1 = _clock_register(r1, _R1_LEN, _R1_TAPS, _feedback(r1, _R1_LEN, _R1_TAPS) ^ fb)
            r2 = _clock_register(r2, _R2_LEN, _R2_TAPS, _feedback(r2, _R2_LEN, _R2_TAPS) ^ fb)
            r3 = _clock_register(r3, _R3_LEN, _R3_TAPS, _feedback(r3, _R3_LEN, _R3_TAPS) ^ fb)
        for i in range(22):
            fb = f[i]
            r1 = _clock_register(r1, _R1_LEN, _R1_TAPS, _feedback(r1, _R1_LEN, _R1_TAPS) ^ fb)
            r2 = _clock_register(r2, _R2_LEN, _R2_TAPS, _feedback(r2, _R2_LEN, _R2_TAPS) ^ fb)
            r3 = _clock_register(r3, _R3_LEN, _R3_TAPS, _feedback(r3, _R3_LEN, _R3_TAPS) ^ fb)
        for _ in range(100):
            r1, r2, r3 = self._irregular_clock(r1, r2, r3)

        out: List[int] = []
        for _ in range(nbits):
            out.append((r1 & 1) ^ (r2 & 1) ^ (r3 & 1))
            r1, r2, r3 = self._irregular_clock(r1, r2, r3)
        return out

    @staticmethod
    def _irregular_clock(r1, r2, r3):
        # Clock bit for each register is bit 8 of R1, bit 10 of R2, bit 10 of R3.
        b1 = (r1 >> 8) & 1
        b2 = (r2 >> 10) & 1
        b3 = (r3 >> 10) & 1
        maj = (b1 & b2) | (b1 & b3) | (b2 & b3)
        if b1 == maj:
            r1 = _clock_register(r1, _R1_LEN, _R1_TAPS, _feedback(r1, _R1_LEN, _R1_TAPS))
        if b2 == maj:
            r2 = _clock_register(r2, _R2_LEN, _R2_TAPS, _feedback(r2, _R2_LEN, _R2_TAPS))
        if b3 == maj:
            r3 = _clock_register(r3, _R3_LEN, _R3_TAPS, _feedback(r3, _R3_LEN, _R3_TAPS))
        return r1, r2, r3


if __name__ == "__main__":
    # Published A5/1 test vector (GSM session key example widely used in the
    # literature / gr-gsm tests):
    #   key = 0x1223456789ABCDEF, frame = 0x000134
    #   first 64 keystream bits -> bytes 53 4e aa 58 2f e8 15 1a  (LSB-first packing)
    a51 = A51()
    ks = a51.keystream(bytes.fromhex("1223456789ABCDEF"), bytes.fromhex("000134"), 64)
    from analyzer.ingest import bits_to_bytes
    hexval = bits_to_bytes(ks, "lsb").hex()
    expected = "534eaa582fe8151a"
    if hexval == expected:
        print(f"OK: A5/1 matches test vector (first 8 keystream bytes = {hexval})")
    else:
        print(f"FAIL: A5/1 got {hexval}, expected {expected}")
