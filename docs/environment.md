# Environment setup

The toolchain has two tiers of dependencies:

* **Tier 0 (already required, pure Python)**: `numpy`, `scipy`, `sympy`,
  `matplotlib`, `pycryptodome`. Everything except TESTU01, C software
  benchmarks, and SAT/Gröbner solvers runs on this tier.
* **Tier 1 (optional, needs WSL)**: `gcc` + TESTU01 (BigCrush), C software
  throughput benchmarks, CryptoMiniSat (SAT), SageMath (Gröbner).

## 1. Install WSL + Ubuntu (one-time, needs admin)

Run in an **Administrator PowerShell**:

```powershell
wsl --install -d Ubuntu
```

Reboot if prompted, then open Ubuntu and set a UNIX username/password. Then:

```bash
sudo apt update
sudo apt install -y build-essential git
```

Verify:

```bash
wsl gcc --version
```

## 2. Install TestU01 + battery driver (one-time)

TestU01 is in Ubuntu's `multiverse` repository — no source build needed:

```bash
sudo apt update
sudo apt install -y testu01-bin libtestu01-0-dev
```

Then compile the battery driver (reads 32-bit decimal integers and runs the
batteries). Adjust `/mnt/d/...` to your workspace path:

```bash
gcc -O2 -o /root/testu01_driver /mnt/d/hardness/stream-cipher-analyzer/analyzer/testu01_driver.c \
    -ltestu01 -ltestu01mylib -ltestu01probdist -lm
```

The Python wrapper `analyzer/rng_testu01.py` invokes
`wsl -u root -e /root/testu01_driver <battery> <textfile>`.

### Keystream data requirements (prepare the input)

Pack keystream bits into 32-bit words (LSB-first), then write each word as a
decimal integer, one per line. Approximate total keystream bits per battery:

| Battery    | bits            | ~words (32-bit) |
|------------|-----------------|-----------------|
| SmallCrush | 2^28 (~320 Mbit)| ~10 M           |
| Crush      | 2^35 (~34 Gbit) | ~1 G            |
| BigCrush   | 2^38 (~274 Gbit)| ~8 G            |

SmallCrush is the quick local check; BigCrush needs tens of GB (use the cloud
or stream it).

## 3. Python packages

Tier 0 packages are typically already present. On a fresh machine:

```bash
pip install numpy scipy sympy matplotlib pycryptodome
```

Optional extras (only if needed and pip works in the target environment):

```bash
pip install pandas statsmodels galois z3-solver
```

> Note: on the reference sandbox (Python 3.14 + pip 26.x), wheel-metadata
> extraction fails under the file sandbox; the fallback is to download wheels
> with `pip download` and extract them manually into a `vendor/` directory, or
> to upgrade pip. These packages are conveniences, not required for the core
> pipeline (tables/CSV are generated with the stdlib `csv` module).

## 4. C software benchmark

Compile the cipher reference to C (from the MATLAB/Python spec) and time it at
`-O3` under WSL. Report `MB/s` and `cycles/byte`; Python is NOT a valid
throughput benchmark.
