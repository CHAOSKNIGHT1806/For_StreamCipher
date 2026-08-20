"""Download wheels directly from PyPI and extract them into ``vendor/``.

Bypasses pip's installer, which fails inside the DeepSeekHarness sandbox
(pip 26.x extracts wheel metadata into a ``tempfile.mkdtemp`` directory whose
writes the sandbox denies).  This script uses ``urllib`` + ``zipfile`` only.

Usage (from the tool root)::

    python scripts/install_deps.py

The packages are OPTIONAL conveniences (z3 = SAT, galois = GF fields,
pandas = tables, statsmodels = distributions).  ``cli.py`` automatically adds
``vendor/`` to ``sys.path`` when it exists.
"""

import json
import os
import sys
import urllib.request
import zipfile

PKGS = ["z3-solver", "galois", "pandas", "statsmodels", "numba", "llvmlite", "patsy"]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "vendor")
os.makedirs(VENDOR, exist_ok=True)

_CP_TAG = f"cp{sys.version_info.major}{sys.version_info.minor}"


def pick_wheel(files):
    """Prefer exact cp<py>-win_amd64, then any win_amd64, then py3-none-any, then any."""
    for pref in (_CP_TAG + "-win_amd64", "win_amd64", "py3-none-any"):
        for f in files:
            fn = f["filename"]
            if fn.endswith(".whl") and pref in fn:
                return f["url"], fn
    for f in files:
        if f["filename"].endswith(".whl"):
            return f["url"], f["filename"]
    return None, None


def main() -> int:
    failed = []
    for pkg in PKGS:
        try:
            data = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=30))
            url, fn = pick_wheel(data["urls"])
            if not url:
                print(f"SKIP {pkg}: no wheel found")
                failed.append(pkg)
                continue
            dest = os.path.join(VENDOR, fn)
            print(f"downloading {fn} ...")
            urllib.request.urlretrieve(url, dest)
            with zipfile.ZipFile(dest) as z:
                z.extractall(VENDOR)
            os.remove(dest)
            print(f"OK   {pkg}")
        except Exception as e:  # noqa: BLE001
            print(f"FAIL {pkg}: {e!r}")
            failed.append(pkg)
    print(f"\ndone. failed: {failed if failed else 'none'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
