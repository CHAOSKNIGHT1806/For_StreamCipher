"""Run every smoke test and report a pass/fail summary (CI-style entry point)."""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TESTS = ["smoke1.py", "smoke2.py", "smoke3.py", "smoke4.py"]


def main() -> int:
    failed = 0
    for t in TESTS:
        path = os.path.join(ROOT, "tests", t)
        print(f"--- {t} ---")
        r = subprocess.run([sys.executable, path], cwd=ROOT)
        if r.returncode != 0:
            failed += 1
            print(f"[FAIL] {t}")
    print(f"\n{len(TESTS) - failed}/{len(TESTS)} smoke suites passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
