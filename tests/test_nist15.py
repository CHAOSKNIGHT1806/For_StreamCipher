"""Verify all 15 NIST tests run and produce sane p-values on random data.

Note on multi-p-value tests: ``non_overlapping_template`` (148 sub-tests),
``random_excursions`` (8), ``random_excursions_variant`` (18) use the NIST
"all sub-tests pass" criterion, i.e. ``min(p_values) >= alpha``. For random
data the expected pass rate is therefore ``(1-alpha)^k`` (e.g. ~0.23 for
148 sub-tests), not ~1.0 — that is correct, not a failure.
"""

import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.rng_nist import _TESTS, run_battery  # noqa: E402

MULTI = {"non_overlapping_template", "random_excursions", "random_excursions_variant"}


def main() -> int:
    assert len(_TESTS) == 15, f"expected 15 tests, got {len(_TESTS)}"
    random.seed(7)
    seqs = [[random.getrandbits(1) for _ in range(40000)] for _ in range(8)]
    b = run_battery(seqs)

    failed = 0
    for name, res in b.items():
        tag = "multi" if name in MULTI else "single"
        print(f"{name:26s} [{tag}] pass={res['pass_rate']:.2f}  mean_p={res['mean_p']:.3f}")
        if name not in MULTI and res["pass_rate"] < 0.8:
            print(f"  [FAIL] {name}: pass_rate {res['pass_rate']} too low for random data")
            failed += 1

    print("OK" if not failed else "FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
