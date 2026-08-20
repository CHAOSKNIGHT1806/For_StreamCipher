import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.correlation import best_linear_approximation  # noqa: E402
from analyzer.cube import recover_linear_superpoly, test_linear_superpoly  # noqa: E402
from analyzer.ca_model import rule_number_to_table  # noqa: E402
from analyzer.rng_nist import run_battery  # noqa: E402
from analyzer.report import (  # noqa: E402
    nist_report_table,
    plot_autocorrelation,
    plot_linear_complexity,
    plot_pvalue_histogram,
)

OUT = os.path.join(ROOT, "results")

# 1) run_battery on pseudo-random sequences
random.seed(7)
seqs = [[random.getrandbits(1) for _ in range(20000)] for _ in range(6)]
battery = run_battery(seqs)
print("battery pass rates:")
for name, res in battery.items():
    print(f"  {name:20s} pass_rate={res['pass_rate']:.3f} uniformity_p={res['uniformity_p']:.3f}")
nist_report_table(battery, outdir=OUT)
assert os.path.exists(os.path.join(OUT, "nist_summary.csv"))
assert os.path.exists(os.path.join(OUT, "nist_summary.tex"))
print("OK  nist_report_table -> CSV + LaTeX")

# 2) figures
plot_linear_complexity([k // 2 + (k % 3) for k in range(1, 501)], outdir=OUT)
plot_autocorrelation(list(range(1, 33)), [0.01 * (k % 5) for k in range(1, 33)], n=20000, outdir=OUT)
plot_pvalue_histogram(battery["frequency"]["p_values"], outdir=OUT)
for f in ["linear_complexity.pdf", "autocorrelation.pdf", "pvalue_hist.pdf"]:
    assert os.path.exists(os.path.join(OUT, f)), f
print("OK  figures -> PDF + PNG")

# 3) cube superpoly recovery on f = x0 + x1*x2*x3 + x0*x1*x2, cube={1,2}
def f(bits):
    return bits[0] ^ (bits[1] & bits[2] & bits[3]) ^ (bits[0] & bits[1] & bits[2])

cube = [1, 2]
nvars = 4
assert test_linear_superpoly(f, cube, nvars) is True
res = recover_linear_superpoly(f, cube, nvars)
assert res["constant"] == 0, res
assert res["coefficients"] == {0: 1, 3: 1}, res
print("OK  cube superpoly recovery ->", res)

# 4) best linear approximation of rule 30 (expect correlation 0.5, mask 0b111)
mask, c = best_linear_approximation(rule_number_to_table(30))
assert abs(c - 0.5) < 1e-9, (mask, c)
assert mask in (4, 7), mask  # several masks reach max |W|=4 for rule 30
print(f"OK  rule30 best linear approx -> mask={mask}, correlation={c}")

print("ALL SMOKE2 TESTS PASSED")
