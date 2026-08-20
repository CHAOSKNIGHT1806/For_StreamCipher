import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.linear import berlekamp_massey  # noqa: E402
from analyzer.stats import block_chi_square, monobit, runs_test  # noqa: E402
from analyzer.ingest import bits_to_bytes, bytes_to_bits  # noqa: E402
from analyzer.rng_nist import (  # noqa: E402
    approximate_entropy,
    binary_matrix_rank,
    block_frequency,
    cusum,
    dft,
    frequency,
    linear_complexity_test,
    longest_run_ones,
    maurer_universal,
    overlapping_template,
    runs,
    serial,
)

# 1) BM on x^4 + x + 1 (period 15, linear complexity 4)
s = [1, 0, 0, 0]
for _ in range(11):
    s.append(s[-1] ^ s[-4])
L, C = berlekamp_massey(s)
assert L == 4, f"BM L={L}, expected 4"
print(f"OK  BM x^4+x+1 -> L={L}, C[0:5]={C[:5]}")

# 2) bits<->bytes roundtrip
bits = [1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1]
assert bytes_to_bits(bits_to_bytes(bits))[:16] == bits
print("OK  bits<->bytes roundtrip")

# 3) stats + NIST on deterministic pseudo-random data
random.seed(42)
r = [random.getrandbits(1) for _ in range(100000)]
print("monobit z            =", round(monobit(r)["z"], 3))
print("runs z               =", round(runs_test(r)["z"], 3))
print("block chi2 p         =", round(block_chi_square(r, 8)["p"], 3))
print("NIST frequency       p =", round(frequency(r)["p_value"], 4))
print("NIST block_frequency p =", round(block_frequency(r)["p_value"], 4))
print("NIST runs            p =", round(runs(r)["p_value"], 4))
print("NIST longest_run     p =", round(longest_run_ones(r)["p_value"], 4))
print("NIST rank            p =", round(binary_matrix_rank(r)["p_value"], 4))
print("NIST dft             p =", round(dft(r)["p_value"], 4))
print("NIST overlapping     p =", round(overlapping_template(r)["p_value"], 4))
print("NIST maurer(L=7)     p =", round(maurer_universal(r, 7)["p_value"], 4))
print("NIST serial       p1/p2 =", round(serial(r)["p_value1"], 4), round(serial(r)["p_value2"], 4))
print("NIST ApEn            p =", round(approximate_entropy(r)["p_value"], 4))
print("NIST cusum     fwd/bwd =", round(cusum(r)["p_value_forward"], 4), round(cusum(r)["p_value_backward"], 4))
print("NIST linear_complexity p =", round(linear_complexity_test(r)["p_value"], 4))
print("ALL SMOKE TESTS PASSED")
