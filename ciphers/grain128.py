"""Grain-128 v1 stream cipher (Hell, Johansson, Meier — eSTREAM).

128-bit key, 96-bit IV.  Two 128-bit shift registers (LFSR f(x) and NFSR g(x))
plus a nonlinear filter h(x).  Bit-serial reference implementation, verified
against the BouncyCastle Grain128 test vectors.

Register model: index 0 is the first-loaded bit (b_0 = key bit 0, s_0 = IV bit
0).  Key and IV bits are loaded LSB-first per byte (b_0 = LSB of key byte 0),
matching ``ingest.bytes_to_bits(..., "lsb")``.  The keystream bit list is also
LSB-first: bit 0 is the first generated bit and is the LSB of the first
keystream byte.
"""
from __future__ import annotations

import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ingest import CipherAdapter, bytes_to_bits


def _clock(key_bits: List[int], iv_bits: List[int], nbits: int) -> List[int]:
    # LFSR s (128 bits), NFSR b (128 bits); index 0 = lowest.
    s = [0] * 128
    b = [0] * 128
    for i in range(128):
        b[i] = key_bits[i]
    for i in range(96):
        s[i] = iv_bits[i]
    for i in range(96, 128):
        s[i] = 1

    def lfsr_fb():
        return s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96]

    def nfsr_fb():
        return (b[0] ^ b[26] ^ b[56] ^ b[91] ^ b[96]
                ^ (b[3] & b[67]) ^ (b[11] & b[13]) ^ (b[17] & b[18])
                ^ (b[27] & b[59]) ^ (b[40] & b[48]) ^ (b[61] & b[65])
                ^ (b[68] & b[84]))

    def output():
        h = ((b[12] & s[8]) ^ (s[13] & s[20]) ^ (b[95] & s[42])
             ^ (s[60] & s[79]) ^ (b[12] & b[95] & s[94]))
        return (h ^ s[93] ^ b[2] ^ b[15] ^ b[36] ^ b[45] ^ b[64]
                ^ b[73] ^ b[89])

    # 256 clocks of initialization, output fed back.
    for _ in range(256):
        z = output()
        nf = lfsr_fb() ^ z
        bf = nfsr_fb() ^ s[0] ^ z
        s = s[1:] + [nf]
        b = b[1:] + [bf]

    # Keystream generation.
    out: List[int] = []
    for _ in range(nbits):
        z = output()
        out.append(z)
        st = s[0]  # current s_t before shifting
        s = s[1:] + [lfsr_fb()]
        b = b[1:] + [nfsr_fb() ^ st]
    return out


class Grain128(CipherAdapter):
    name = "Grain-128"
    key_size = 128   # bits
    iv_size = 96     # bits
    state_size = 256  # bits (128 LFSR + 128 NFSR)

    def keystream(self, key: bytes, iv: bytes, nbits: int) -> List[int]:
        key = key[:16].ljust(16, b"\x00")
        iv = iv[:12].ljust(12, b"\x00")
        return _clock(bytes_to_bits(key, "lsb"), bytes_to_bits(iv, "lsb"), nbits)


if __name__ == "__main__":
    from analyzer.ingest import bits_to_bytes

    # BouncyCastle Grain128 test vector 1: all-zero key and IV.
    ks = Grain128().keystream(bytes(16), bytes(12), 128)
    hexval = bits_to_bytes(ks, "lsb").hex()
    expected = "4bdb20824c5dce6fc63e94456c3281d4"
    if hexval == expected:
        print(f"OK: Grain-128 matches test vector 1 ({hexval})")
    else:
        print(f"FAIL: Grain-128 test 1 got {hexval}, expected {expected}")

    # BouncyCastle Grain128 test vector 2.
    ks2 = Grain128().keystream(
        bytes.fromhex("0123456789abcdef123456789abcdef0"),
        bytes.fromhex("0123456789abcdef12345678"), 128)
    hexval2 = bits_to_bytes(ks2, "lsb").hex()
    expected2 = "ba399daf90df8eba103d9ea83c805904"
    if hexval2 == expected2:
        print(f"OK: Grain-128 matches test vector 2 ({hexval2})")
    else:
        print(f"FAIL: Grain-128 test 2 got {hexval2}, expected {expected2}")
