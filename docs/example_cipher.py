"""Example: wrapping a CA-based stream cipher as a CipherAdapter.

Copy this file, implement ``keystream`` (and optionally the structural hooks),
then run:

    python cli.py analyze docs/example_cipher.py:Rule30Cipher
    python cli.py report  docs/example_cipher.py:Rule30Cipher --rule 30 --cells 64 --key-bits 64
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ca_model import ca_step          # noqa: E402
from analyzer.ingest import CipherAdapter, bytes_to_bits  # noqa: E402


class Rule30Cipher(CipherAdapter):
    """A minimal toy: rule-30 CA, 64 seed bits -> state, taps cell 0 each step."""

    name = "toy-rule30"
    key_size = 64       # bits (seed cells)
    iv_size = 0
    state_size = 64

    rule = 30
    boundary = "periodic"

    def _seed_to_state(self, key: bytes) -> list:
        bits = bytes_to_bits(key)             # LSB-first within each byte
        if len(bits) < self.state_size:
            bits = bits + [0] * (self.state_size - len(bits))
        bits = bits[: self.state_size]
        # rule 30 has the all-zero FIXED POINT: an all-zero state stays all-zero.
        # A real design must escape this (the tool would otherwise report a
        # trivially degenerate keystream -- itself a useful diagnostic).
        if not any(bits):
            bits[0] = 1
        return bits

    # ---- black-box (REQUIRED) ----
    def keystream(self, key: bytes, iv: bytes, nbits: int) -> list:
        state = self._seed_to_state(key)
        bits = []
        for _ in range(nbits):
            bits.append(state[0])             # tap cell 0 (example)
            state = ca_step(state, self.rule, self.boundary)
        return bits

    # ---- structural hooks (OPTIONAL — unlock algebraic/security layers) ----
    def init(self, key: bytes, iv: bytes):
        return self._seed_to_state(key)

    def step(self, state):
        return ca_step(state, self.rule, self.boundary), [state[0]]


if __name__ == "__main__":
    c = Rule30Cipher()
    ks = c.keystream(b"\x01" * 8, b"", 1000)
    print("generated", len(ks), "bits; first 16:", ks[:16])
