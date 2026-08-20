"""Paper-ready figures, tables, and report scaffolding (IEEE TIFS default).

Depends only on numpy + matplotlib (both in the base scientific stack). All
figures are written as PDF (vector) + PNG; tables as LaTeX + CSV.
"""

from __future__ import annotations

import csv
import math
import os
from typing import Iterable, List, Optional, Sequence

# Keep matplotlib's font cache inside the project (sandbox-safe).
_mpldir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".mplconfig")
os.environ.setdefault("MPLCONFIGDIR", _mpldir)

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

__all__ = [
    "save_fig",
    "plot_linear_complexity",
    "plot_autocorrelation",
    "plot_pvalue_histogram",
    "plot_scaling",
    "csv_table",
    "latex_table",
    "nist_report_table",
]


def _style() -> None:
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.titlesize": 12,
        "legend.fontsize": 10,
        "figure.dpi": 110,
        "savefig.bbox": "tight",
    })


def save_fig(fig, outdir: str, name: str) -> List[str]:
    os.makedirs(outdir, exist_ok=True)
    paths = [os.path.join(outdir, name + ".pdf"), os.path.join(outdir, name + ".png")]
    fig.savefig(paths[0])
    fig.savefig(paths[1])
    plt.close(fig)
    return paths


# --------------------------------------------------------------------------- #
# Figures
# --------------------------------------------------------------------------- #
def plot_linear_complexity(profile: Sequence[int], outdir: str = "results",
                           name: str = "linear_complexity") -> List[str]:
    _style()
    k = list(range(1, len(profile) + 1))
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(k, list(profile), lw=1.2, label="linear complexity $L_k$")
    ax.plot([1, len(profile)], [0.5, len(profile) / 2.0], ls="--", color="gray", label="$n/2$ (random)")
    ax.set_xlabel("prefix length $k$")
    ax.set_ylabel("$L_k$")
    ax.set_title("Linear complexity profile")
    ax.legend()
    return save_fig(fig, outdir, name)


def plot_autocorrelation(lags: Sequence[int], values: Sequence[float], n: int,
                         outdir: str = "results", name: str = "autocorrelation") -> List[str]:
    _style()
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.vlines(lags, 0, list(values), color="C0", lw=1.2)
    ax.plot(lags, list(values), "o", color="C0", ms=3)
    bound = 2.5758 / math.sqrt(n)
    ax.axhline(bound, color="r", ls="--", lw=1)
    ax.axhline(-bound, color="r", ls="--", lw=1)
    ax.set_xlabel("lag $k$")
    ax.set_ylabel("$A(k)$")
    ax.set_title("Normalized autocorrelation (1% bounds)")
    return save_fig(fig, outdir, name)


def plot_pvalue_histogram(pvalues: Sequence[float], outdir: str = "results",
                          name: str = "pvalue_hist", title: str = "p-value distribution") -> List[str]:
    _style()
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist(list(pvalues), bins=10, range=(0, 1), edgecolor="black")
    ax.set_xlabel("p-value")
    ax.set_ylabel("count")
    ax.set_title(title)
    return save_fig(fig, outdir, name)


def plot_scaling(x: Sequence[float], y: Sequence[float], outdir: str = "results",
                 name: str = "scaling", xlabel: str = "rounds", ylabel: str = "time (s)",
                 logy: bool = True) -> List[str]:
    _style()
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(list(x), list(y), marker="o")
    if logy:
        ax.set_yscale("log")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title("Attack cost scaling")
    return save_fig(fig, outdir, name)


# --------------------------------------------------------------------------- #
# Tables
# --------------------------------------------------------------------------- #
def csv_table(headers: Sequence[str], rows: Sequence[Sequence], outdir: str, name: str) -> str:
    os.makedirs(outdir, exist_ok=True)
    p = os.path.join(outdir, name + ".csv")
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(list(headers))
        for r in rows:
            w.writerow([str(c) for c in r])
    return p


def _latex_cell(c) -> str:
    return str(c).replace("_", "\\_").replace("%", "\\%").replace("&", "\\&").replace("#", "\\#")


def latex_table(headers: Sequence[str], rows: Sequence[Sequence], outdir: str, name: str,
                caption: str = "", label: str = "tab:data") -> str:
    os.makedirs(outdir, exist_ok=True)
    p = os.path.join(outdir, name + ".tex")
    cols = "l" + "c" * (len(headers) - 1)
    lines = [
        "\\begin{table}[htbp]",
        "  \\centering",
        f"  \\caption{{{caption}}}",
        f"  \\label{{{label}}}",
        f"  \\begin{{tabular}}{{{cols}}}",
        "    \\hline",
        "    " + " & ".join(str(h) for h in headers) + " \\\\",
        "    \\hline",
    ]
    for r in rows:
        lines.append("    " + " & ".join(_latex_cell(c) for c in r) + " \\\\")
    lines += ["    \\hline", "  \\end{tabular}", "\\end{table}"]
    with open(p, "w") as f:
        f.write("\n".join(lines) + "\n")
    return p


def nist_report_table(battery: dict, outdir: str = "results", name: str = "nist_summary") -> List[List[str]]:
    headers = ["Test", "pass rate", "uniformity p", "mean p", "median p"]
    rows: List[List[str]] = []
    for tname, res in battery.items():
        rows.append([
            tname,
            f"{res['pass_rate']:.4f}",
            f"{res['uniformity_p']:.4f}",
            f"{res['mean_p']:.4f}",
            f"{res['median_p']:.4f}",
        ])
    csv_table(headers, rows, outdir, name)
    latex_table(headers, rows, outdir, name,
                caption="NIST SP 800-22 results (standard withdrawn Nov 2022; see text).",
                label="tab:nist")
    return rows
