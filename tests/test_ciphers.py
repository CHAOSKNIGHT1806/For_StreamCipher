"""Sanity-check built-in reference cipher adapters (black-box, no test vectors).

Each registered cipher must emit a non-constant keystream of the requested
length under a nonzero key. (Bit-exact test-vector checks live in each cipher's
own ``if __name__ == "__main__":`` block.)
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ciphers import BUILTIN  # noqa: E402


def main() -> int:
    failed = 0
    for name, cls in BUILTIN.items():
        c = cls()
        key = bytes([0xA5] * (c.key_size // 8 or 16))
        iv = bytes(c.iv_size // 8 or 0)
        ks = c.keystream(key, iv, 4000)
        ok = True
        if len(ks) != 4000:
            print(f"[FAIL] {name}: length {len(ks)} != 4000")
            ok = False
        elif not all(b in (0, 1) for b in ks):
            print(f"[FAIL] {name}: non-bit value in keystream")
            ok = False
        elif len(set(ks)) < 2:
            print(f"[FAIL] {name}: degenerate (constant) keystream")
            ok = False
        else:
            print(f"OK  {name}: 4000 bits, {sum(ks)} ones")
        if not ok:
            failed += 1
    print(f"\n{len(BUILTIN) - failed}/{len(BUILTIN)} ciphers passed sanity check")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
