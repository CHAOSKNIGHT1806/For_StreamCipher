#!/usr/bin/env python3
"""Command-line entry point for the stream-cipher security analyzer.

Examples
--------
    python cli.py list
    python cli.py ca-screen --rules 90 30 150 110
    python cli.py compare
    python cli.py analyze chacha20 --nseq 10 --nbits 1000000
    python cli.py analyze path/to/my_cipher.py:MyCipher --nseq 10 --nbits 1000000
    python cli.py report my_cipher.py:MyCipher --rule 30 --cells 64 --key-bits 128
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Optional local vendor/ install (sandbox workaround for pip): expose it if present.
_VENDOR = os.path.join(ROOT, "vendor")
if os.path.isdir(_VENDOR) and _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

from analyzer.ca_model import screen_linear_degeneration  # noqa: E402
from analyzer.comparison import ca_attack_surface_table, comparison_table  # noqa: E402
from analyzer.empirical import empirical_comparison  # noqa: E402
from analyzer.ingest import generate_samples  # noqa: E402
from analyzer.linear import linear_complexity, linear_complexity_profile  # noqa: E402
from analyzer.performance import ca_fpga_estimate  # noqa: E402
from analyzer.report import (  # noqa: E402
    csv_table,
    nist_report_table,
    plot_autocorrelation,
    plot_linear_complexity,
)
from analyzer.report_builder import build_report  # noqa: E402
from analyzer.rng_nist import run_battery  # noqa: E402
from analyzer.security import forward_backward_summary  # noqa: E402
from analyzer.stats import summary_stats  # noqa: E402


def load_adapter(spec: str):
    """Resolve a cipher spec: builtin name, or 'path/to/module.py:ClassName'."""
    if ":" in spec:
        path, cls_name = spec.rsplit(":", 1)
        modname = os.path.splitext(os.path.basename(path))[0]
        specobj = importlib.util.spec_from_file_location(modname, path)
        mod = importlib.util.module_from_spec(specobj)
        specobj.loader.exec_module(mod)
        return getattr(mod, cls_name)()
    from ciphers import BUILTIN
    if spec in BUILTIN:
        return BUILTIN[spec]()
    raise ValueError(f"unknown cipher spec: {spec!r}")


def cmd_list(_args) -> None:
    from ciphers import BUILTIN
    for name, cls in BUILTIN.items():
        print(f"{name:14s} key={cls.key_size} bits  iv={cls.iv_size} bits")


def run_blackbox(adapter, args) -> dict:
    """Run the black-box battery; return a results dict for reporting."""
    print(f"== analyzing {adapter.name} ({args.nseq} x {args.nbits} bits) ==")
    key = bytes.fromhex(args.key) if args.key else bytes(adapter.key_size // 8 or 16)
    seqs = list(generate_samples(adapter, args.nseq, args.nbits, key=key, iv_mode=args.iv_mode))

    battery = run_battery(seqs)
    nist_report_table(battery, outdir=args.outdir)

    head = seqs[0][: args.profile_len]
    prof = linear_complexity_profile(head)
    plot_linear_complexity(prof, outdir=args.outdir)
    lc = linear_complexity(head)

    st = summary_stats(seqs[0])
    plot_autocorrelation([r["lag"] for r in st["autocorr"]],
                         [r["A"] for r in st["autocorr"]],
                         len(seqs[0]), outdir=args.outdir)

    print("\nNIST SP 800-22 summary (withdrawn standard):")
    for name, res in battery.items():
        print(f"  {name:20s} pass_rate={res['pass_rate']:.3f}  uniformity_p={res['uniformity_p']:.3f}")
    print(f"\nlinear complexity (first {args.profile_len} bits): {lc} (expect ~{args.profile_len // 2})")
    print(f"monobit z = {st['monobit']['z']:.3f}   runs z = {st['runs']['z']:.3f}")
    return {"battery": battery, "lc": lc, "lc_len": args.profile_len, "stats": st,
            "adapter": adapter, "seqs": seqs}


def cmd_analyze(args) -> None:
    adapter = load_adapter(args.cipher)
    run_blackbox(adapter, args)
    print(f"\noutputs written to {args.outdir}/")


def cmd_report(args) -> None:
    adapter = load_adapter(args.cipher)
    r = run_blackbox(adapter, args)

    ca_screen = None
    security = None
    fpga = None
    if args.rule is not None:
        ca_screen = {}
        for rule in args.rule:
            ca_screen[rule] = screen_linear_degeneration(rule, n=args.cells, nbits=args.nbits)
        security = forward_backward_summary(
            rule=args.rule[0], n=args.cells, key_bits=args.key_bits,
            construction_type=args.construction)
        fpga = ca_fpga_estimate(args.cells, args.output_bits_per_cycle, freq_mhz=args.freq_mhz)

    comparison_table(outdir=args.outdir)
    ca_attack_surface_table(outdir=args.outdir)
    path = build_report(adapter.name, outdir=args.outdir, battery=r["battery"],
                        lc=r["lc"], lc_len=r["lc_len"], stats=r["stats"],
                        ca_screen=ca_screen, security=security, fpga=fpga)
    print(f"\nreport written to {path}")


def cmd_ca_screen(args) -> None:
    for rule in args.rules:
        r = screen_linear_degeneration(rule, n=args.n, nbits=args.nbits)
        flag = "DEGENERATE (linear)" if r["degenerate"] else "ok"
        print(f"rule {rule:3d}: LC={r['linear_complexity']:5d}  ratio={r['ratio']:.3f}  {flag}")


def cmd_compare(_args) -> None:
    comparison_table(outdir=_args.outdir)
    ca_attack_surface_table(outdir=_args.outdir)
    print(f"comparison + CA attack-surface tables written to {_args.outdir}/")


def cmd_empirical(args) -> None:
    from ciphers import BUILTIN
    rows = empirical_comparison([BUILTIN[n]() for n in BUILTIN], nbits=args.nbits)
    headers = ["cipher", "linear_complexity", "monobit_z", "runs_z", "prop_ones"]
    for r in rows:
        print(f"{r['cipher']:12s} LC={r['linear_complexity']:5d}  "
              f"monobit_z={r['monobit_z']:7.3f}  runs_z={r['runs_z']:7.3f}  ones={r['prop_ones']:.4f}")
    csv_table(headers, [[r[h] for h in headers] for r in rows], args.outdir, "empirical_comparison")


def _add_blackbox_args(p) -> None:
    p.add_argument("cipher")
    p.add_argument("--nseq", type=int, default=10)
    p.add_argument("--nbits", type=int, default=1000000)
    p.add_argument("--key", default=None, help="hex key (default: zeros)")
    p.add_argument("--iv-mode", default="counter", choices=["counter", "random", "none"])
    p.add_argument("--profile-len", type=int, default=4096)
    p.add_argument("--outdir", default="results")


def main() -> None:
    p = argparse.ArgumentParser(prog="stream-analyzer", description="Stream cipher security analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list built-in cipher adapters")

    a = sub.add_parser("analyze", help="black-box analysis (NIST + linear complexity + stats + figures)")
    _add_blackbox_args(a)

    r = sub.add_parser("report", help="full black-box analysis + comparison + report")
    _add_blackbox_args(r)
    r.add_argument("--rule", type=int, nargs="+", default=None, help="CA rule(s) for structural/security analysis")
    r.add_argument("--cells", type=int, default=64)
    r.add_argument("--key-bits", type=int, default=None)
    r.add_argument("--construction", default="heuristic",
                   choices=["heuristic", "prf", "number_theory", "lattice"])
    r.add_argument("--output-bits-per-cycle", type=int, default=1)
    r.add_argument("--freq-mhz", type=float, default=100.0)

    c = sub.add_parser("ca-screen", help="CA linear-degeneration screen")
    c.add_argument("--rules", type=int, nargs="+", default=[90, 30, 150, 110])
    c.add_argument("--n", type=int, default=64)
    c.add_argument("--nbits", type=int, default=4096)

    cp = sub.add_parser("compare", help="generate reference comparison tables")
    cp.add_argument("--outdir", default="results")

    ep = sub.add_parser("empirical", help="measured black-box comparison of registered ciphers")
    ep.add_argument("--nbits", type=int, default=20000)
    ep.add_argument("--outdir", default="results")

    args = p.parse_args()
    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "analyze":
        cmd_analyze(args)
    elif args.cmd == "report":
        cmd_report(args)
    elif args.cmd == "ca-screen":
        cmd_ca_screen(args)
    elif args.cmd == "compare":
        cmd_compare(args)
    elif args.cmd == "empirical":
        cmd_empirical(args)


if __name__ == "__main__":
    main()
