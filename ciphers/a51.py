"""A5/1 stream cipher (GSM over-the-air).

64-bit key (Kc), 22-bit frame number.  Three LFSRs (19, 22, 23 bits) with a
majority clocking rule.  Faithful reference implementation following the
Briceno/Goldberg/Wagner C reference and the Kak (Purdue) Python port.

Register model: bit index 0 is the LSB (left end), the MSB is at the highest
index.  ``clockone`` shifts bits toward the higher index (``shift_right(1)``)
and inserts the feedback parity at bit 0.  During key/frame loading the key bit
is XORed into bit 0 *after* the shift.  The output bit is the XOR of the three
MSBs (R1[-1] ^ R2[-1] ^ R3[-1]).

Key/frame bit order: each key byte contributes its bits MSB-of-byte-first to the
BitVector byte, then the whole byte is reversed, so key bit ``i`` is the LSB of
byte ``i`` — exactly ``ingest.bytes_to_bits(key, "lsb")``.
"""
from __future__ import annotations

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ingest import CipherAdapter, bytes_to_bits

# Register lengths and tap bit indices (index 0 = LSB / left end).
_R1_LEN, _R1_TAPS = 19, (13, 16, 17, 18)
_R2_LEN, _R2_TAPS = 22, (20, 21)
_R3_LEN, _R3_TAPS = 23, (7, 20, 21, 22)

# Clocking bit index for each register (used in majority rule).
_R1_CLK, _R2_CLK, _R3_CLK = 8, 10, 10


def _parity(reg: int, taps) -> int:
    par = 0
    for t in taps:
        par ^= (reg >> t) & 1
    return par


def _clockone(reg: int, length: int, taps) -> int:
    """BitVector-style: record tap parity, shift bits toward higher index,
    insert parity at bit 0."""
    mask = (1 << length) - 1
    p = _parity(reg, taps)
    reg = (reg << 1) & mask
    reg |= p & 1
    return reg


class A51(CipherAdapter):
    name = "A5/1"
    key_size = 64    # bits
    iv_size = 22     # bits (frame number)
    state_size = 64  # bits (19+22+23)

    def keystream(self, key: bytes, iv: bytes, nbits: int) -> List[int]:
        key = key[:8].ljust(8, b"\x00")
        iv = iv[:3].ljust(3, b"\x00")
        k = bytes_to_bits(key, "lsb")      # 64 key bits, LSB of byte 0 first
        # Frame number is a 22-bit integer (big-endian bytes); load its bits
        # LSB-first (bit 0 = LSB of the value), matching BitVector(intVal=...)..reverse().
        frame_val = int.from_bytes(iv, "big") & 0x3FFFFF
        f = [(frame_val >> i) & 1 for i in range(22)]

        r1 = r2 = r3 = 0

        # Load 64 key bits: clock all three, then XOR key bit into bit 0.
        for i in range(64):
            r1 = _clockone(r1, _R1_LEN, _R1_TAPS)
            r2 = _clockone(r2, _R2_LEN, _R2_TAPS)
            r3 = _clockone(r3, _R3_LEN, _R3_TAPS)
            b = k[i]
            r1 ^= b
            r2 ^= b
            r3 ^= b

        # Load 22 frame bits likewise.
        for i in range(22):
            r1 = _clockone(r1, _R1_LEN, _R1_TAPS)
            r2 = _clockone(r2, _R2_LEN, _R2_TAPS)
            r3 = _clockone(r3, _R3_LEN, _R3_TAPS)
            b = f[i]
            r1 ^= b
            r2 ^= b
            r3 ^= b

        def majority():
            s = ((r1 >> _R1_CLK) & 1) + ((r2 >> _R2_CLK) & 1) + ((r3 >> _R3_CLK) & 1)
            return 1 if s >= 2 else 0

        # 100 warm-up clocks with majority clocking, output discarded.
        for _ in range(100):
            maj = majority()
            if ((r1 >> _R1_CLK) & 1) == maj:
                r1 = _clockone(r1, _R1_LEN, _R1_TAPS)
            if ((r2 >> _R2_CLK) & 1) == maj:
                r2 = _clockone(r2, _R2_LEN, _R2_TAPS)
            if ((r3 >> _R3_CLK) & 1) == maj:
                r3 = _clockone(r3, _R3_LEN, _R3_TAPS)

        out: List[int] = []
        for _ in range(nbits):
            maj = majority()
            if ((r1 >> _R1_CLK) & 1) == maj:
                r1 = _clockone(r1, _R1_LEN, _R1_TAPS)
            if ((r2 >> _R2_CLK) & 1) == maj:
                r2 = _clockone(r2, _R2_LEN, _R2_TAPS)
            if ((r3 >> _R3_CLK) & 1) == maj:
                r3 = _clockone(r3, _R3_LEN, _R3_TAPS)
            # Output = XOR of MSBs.
            out.append(
                ((r1 >> (_R1_LEN - 1)) & 1)
                ^ ((r2 >> (_R2_LEN - 1)) & 1)
                ^ ((r3 >> (_R3_LEN - 1)) & 1)
            )
        # A5/1 emits the first keystream bit as the MSB of the first byte
        # (standard test-vector layout: byte 0 = 0x53).  Pack chronologically
        # MSB-first into bytes, then unpack LSB-first so the returned list uses
        # the toolchain's LSB-first-per-byte convention.
        nbytes = (nbits + 7) // 8
        raw = bytearray(nbytes)
        for i in range(nbits):
            raw[i // 8] |= out[i] << (7 - (i % 8))
        return bytes_to_bits(bytes(raw), "lsb")[:nbits]


if __name__ == "__main__":
    # Briceno/Goldberg/Wagner test vector (also in Kak Lecture 32):
    #   key = 1223456789ABCDEF, frame = 0x134
    #   first 114-bit (uplink) keystream begins: 53 4e aa 58 2f e8 15 1a ...
    a51 = A51()
    ks = a51.keystream(bytes.fromhex("1223456789ABCDEF"), bytes.fromhex("000134"), 64)
    from analyzer.ingest import bits_to_bytes
    hexval = bits_to_bytes(ks, "lsb").hex()
    expected = "534eaa582fe8151a"
    if hexval == expected:
        print(f"OK: A5/1 matches test vector (first 8 keystream bytes = {hexval})")
    else:
        print(f"FAIL: A5/1 got {hexval}, expected {expected}")
