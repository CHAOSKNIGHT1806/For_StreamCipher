"""ChaCha20 stream cipher adapter (via pycryptodome)."""

from __future__ import annotations

from typing import List

from Crypto.Cipher import ChaCha20 as _ChaCha

from analyzer.ingest import CipherAdapter, bytes_to_bits


class ChaCha20(CipherAdapter):
    name = "ChaCha20"
    key_size = 256   # bits
    iv_size = 64     # bits (8-byte nonce, original ChaCha20 variant)

    def keystream(self, key: bytes, iv: bytes, nbits: int) -> List[int]:
        nonce = iv[:8] if len(iv) >= 8 else iv.ljust(8, b"\x00")
        cipher = _ChaCha.new(key=key[:32].ljust(32, b"\x00"), nonce=nonce)
        nbytes = (nbits + 7) // 8
        ks = cipher.encrypt(b"\x00" * nbytes)
        return bytes_to_bits(ks)[:nbits]
