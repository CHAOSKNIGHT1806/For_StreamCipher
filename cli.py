#!/usr/bin/env python3
"""Command-line entry point for the stream-cipher security analyzer.

Examples
--------
    python cli.py list
    python cli.py ca-screen --rules 90 30 150 110
    python cli.py analyze chacha20 --nseq 10 --nbits 1000000
    python cli.py analyze path/to/my_cipher.py:MyCipher --nseq 10 --nbits 1000000
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from analyzer.ca_model import screen_linear_degeneration  # noqa: E402
from analyzer.ingest import generate_samples  # noqa: E402
from analyzer.linear import linear_complexity, linear_complexity_profile  # noqa: E402
from analyzer.report import (  # noqa: E402
    nist_report_table,
    plot_autocorrelation,
    plot_linear_complexity,
)
from analyzer.rng_nist import run_battery  # noqa: E402
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


def cmd_analyze(args) -> None:
    adapter = load_adapter(args.cipher)
    print(f"== analyzing {adapter.name} ({args.nseq} x {args.nbits} bits) ==")
    key = bytes.fromhex(args.key) if args.key else bytes(adapter.key_size // 8 or 16)
    seqs = list(generate_samples(adapter, args.nseq, args.nbits, key=key, iv_mode=args.iv_mode))

    battery = run_battery(seqs)
    nist_report_table(battery, outdir=args.outdir)
    print("\nNIST SP 800-22 summary (withdrawn standard):")
    for name, res in battery.items():
        print(f"  {name:20s} pass_rate={res['pass_rate']:.3f}  uniformity_p={res['uniformity_p']:.3f}")

    head = seqs[0][: args.profile_len]
    prof = linear_complexity_profile(head)
    plot_linear_complexity(prof, outdir=args.outdir)
    lc = linear_complexity(head)
    print(f"\nlinear complexity (first {args.profile_len} bits): {lc} (expect ~{args.profile_len // 2})")

    st = summary_stats(seqs[0])
    plot_autocorrelation([r["lag"] for r in st["autocorr"]],
                         [r["A"] for r in st["autocorr"]],
                         len(seqs[0]), outdir=args.outdir)
    print(f"monobit z = {st['monobit']['z']:.3f}   runs z = {st['runs']['z']:.3f}")
    print(f"outputs written to {args.outdir}/")


def cmd_ca_screen(args) -> None:
    for rule in args.rules:
        r = screen_linear_degeneration(rule, n=args.n, nbits=args.nbits)
        flag = "DEGENERATE (linear)" if r["degenerate"] else "ok"
        print(f"rule {rule:3d}: LC={r['linear_complexity']:5d}  ratio={r['ratio']:.3f}  {flag}")


def main() -> None:
    p = argparse.ArgumentParser(prog="stream-analyzer", description="Stream cipher security analyzer")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list built-in cipher adapters")

    a = sub.add_parser("analyze", help="black-box analysis (NIST + linear complexity + stats + figures)")
    a.add_argument("cipher")
    a.add_argument("--nseq", type=int, default=10)
    a.add_argument("--nbits", type=int, default=1000000)
    a.add_argument("--key", default=None, help="hex key (default: zeros)")
    a.add_argument("--iv-mode", default="counter", choices=["counter", "random", "none"])
    a.add_argument("--profile-len", type=int, default=4096)
    a.add_argument("--outdir", default="results")

    c = sub.add_parser("ca-screen", help="CA linear-degeneration screen")
    c.add_argument("--rules", type=int, nargs="+", default=[90, 30, 150, 110])
    c.add_argument("--n", type=int, default=64)
    c.add_argument("--nbits", type=int, default=4096)

    args = p.parse_args()
    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "analyze":
        cmd_analyze(args)
    elif args.cmd == "ca-screen":
        cmd_ca_screen(args)


if __name__ == "__main__":
    main()
