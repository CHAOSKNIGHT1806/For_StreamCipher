import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.security import (  # noqa: E402
    ca_is_bijective,
    forward_backward_summary,
    grover_security_bits,
    provable_security_checklist,
    quantum_security_table,
)
from analyzer.performance import ca_fpga_estimate, throughput_mbps  # noqa: E402

# 1) Grover / post-quantum table
assert grover_security_bits(128) == 64.0
assert grover_security_bits(256) == 128.0
tbl = quantum_security_table([128, 256])
assert tbl[0]["post_quantum_bits"] == 64.0 and tbl[1]["post_quantum_bits"] == 128.0
print("OK  Grover: 128->64, 256->128")

# 2) CA bijectivity (small n)
assert ca_is_bijective(15, 4) is True, "rule 15 (permutive) should be bijective"
assert ca_is_bijective(90, 4) is False, "rule 90 should NOT be bijective"
print("OK  bijectivity: rule15 True, rule90 False")

# 3) provable-security checklist
h = provable_security_checklist("heuristic")
assert "Tier 2" in h["route"]
print("OK  provable checklist (heuristic) ->", h["label"])

# 4) forward/backward summary
s = forward_backward_summary(rule=90, n=8, key_bits=128, construction_type="heuristic")
assert s["state_update_bijective"] is False
assert s["post_quantum_bits"] == 64.0
print("OK  forward/backward summary:", s["backward_security_note"])

# 5) FPGA estimate
est = ca_fpga_estimate(256, 1, freq_mhz=100.0)
assert est["luts"] == 256 and est["ffs"] == 256
assert abs(est["throughput_mbps"] - 100.0) < 1e-9
assert throughput_mbps(8, 100.0) == 800.0
print("OK  FPGA estimate:", {k: est[k] for k in ("luts", "ffs", "throughput_mbps")})

print("ALL SMOKE4 TESTS PASSED")
