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

## 2. Build TESTU01 (one-time)

Inside WSL Ubuntu:

```bash
cd ~
wget http://simul.iro.umontreal.ca/testu01/TestU01-1.2.3.tar.gz
tar xzf TestU01-1.2.3.tar.gz
cd TestU01-1.2.3
./configure --prefix=$HOME/testu01
make -j
make install
```

The Python wrapper (`analyzer/rng_testu01.py`) shells out to the compiled
`birthday`, `smallcrush`, `crush`, `bigcrush` binaries under
`$HOME/testu01/bin`.

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
