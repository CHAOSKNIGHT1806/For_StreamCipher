import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.algebraic import solve_ca  # noqa: E402
from analyzer.ca_model import ca_keystream  # noqa: E402

n, steps, taps = 8, 16, [0]

# 1) linear CA (rule 90): every uniquely-determined initial cell must match seed
seed = [1, 0, 1, 1, 0, 0, 1, 0]
ks = ca_keystream(seed, 90, taps, steps, "periodic")
res = solve_ca(90, n, steps, taps, ks, max_degree=1)
recovered = [res["initial_state"][i] for i in range(n)]
print("rule90 status:", res["status"], "rank:", res["rank"], "/", res["ncols"],
      "| determined cells:", res["determined_count"], "/", n)
print("rule90 recovered:", recovered)
print("rule90 seed     :", seed)
assert res["determined_count"] >= 1
for i in range(n):
    if res["initial_state"][i] is not None:
        assert res["initial_state"][i] == seed[i], (i, recovered, seed)
print("OK  rule90: all determined cells match the true seed")

# 2) nonlinear CA (rule 30): degree-2 linearization builds and reports honestly
seed30 = [1, 1, 0, 1, 0, 0, 1, 1]
ks30 = ca_keystream(seed30, 30, taps, steps, "periodic")
res30 = solve_ca(30, n, steps, taps, ks30, max_degree=2)
print("rule30 degree-2: status", res30["status"], "rank", res30["rank"], "/", res30["ncols"],
      "| rule_degree", res30["rule_degree"])
assert res30["rule_degree"] == 2
assert res30["status"] in ("underdetermined", "unique")
print("OK  rule30: system built (degree 2), honest underdetermined result")

print("ALL SMOKE3 TESTS PASSED")
