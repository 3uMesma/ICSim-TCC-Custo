#!/usr/bin/env python3
"""
plot_lars.py — Gera as figuras finais do artigo LARS (Trilhas A e B).

Produz 4 PNGs:
  fig_trackA_micro.png       ciclos/lookup vs N, painéis hit/miss
  fig_trackA_macro.png       ciclos/frame por estratégia × N, painéis por vetor
  fig_trackB_sender.png      ciclos vs blocos AES + regressão linear
  fig_trackB_gateway.png     COMBINADA: 5 vetores herdados + adversário bem-formado
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


def apply_rcparams():
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.titlesize": 11,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "grid.linestyle": "--",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 120,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
    })


COLORS = {
    "linear":  "#F24822",
    "binary":  "#FFC943",
    "direct":  "#66D575",
    "protect": "#874FFF",
    "verify":  "#66D575",
    "firewall":  "#874FFF",
    "secoc":     "#F24822",
    "spoof-hit":  "#F24822",
    "spoof-miss": "#66D575",
}

ATTACK_LABELS = {
    "dos-py":      "DoS-Python",
    "dos-cangen":  "DoS-cangen",
    "fuzzing":     "Fuzzing",
    "replay":      "Replay",
    "spoofing":    "Spoofing",
    "legit-flood": "Heavy-legit",
    "spoof-wf":    "Spoof-WF",
}


def bootstrap_ci(values, n_boot=2000, ci=95, seed=42):
    rng = np.random.default_rng(seed)
    values = np.asarray(values, dtype=float)
    if len(values) < 2:
        return float(values.mean()) if len(values) else 0.0, 0.0
    means = np.empty(n_boot)
    n = len(values)
    for i in range(n_boot):
        idx = rng.integers(0, n, n)
        means[i] = values[idx].mean()
    lo, hi = np.percentile(means, [(100 - ci) / 2, 100 - (100 - ci) / 2])
    return float(values.mean()), float((hi - lo) / 2)


# ---------------------------------------------------------------------------
# Track A — MICRO (unchanged)
# ---------------------------------------------------------------------------
def fig_trackA_micro(micro_csv, out_dir):
    df = pd.read_csv(micro_csv)
    df = df[df["strategy"] != "baseline"].copy()
    df["cycles_per_lookup"] = pd.to_numeric(df["cycles_per_lookup"], errors="coerce")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), sharey=False)
    strategies = ["linear", "binary", "direct"]
    paths = ["hit", "miss"]

    for ax, path in zip(axes, paths):
        sub = df[df["path"] == path]
        for strat in strategies:
            g = sub[sub["strategy"] == strat].groupby("N")["cycles_per_lookup"]
            xs = sorted(g.groups.keys())
            ys, errs = [], []
            for x in xs:
                m, ci = bootstrap_ci(g.get_group(x).values)
                ys.append(m); errs.append(ci)
            ax.errorbar(xs, ys, yerr=errs,
                        marker="o", markersize=6, capsize=3,
                        color=COLORS[strat], label=strat.capitalize(),
                        linewidth=1.6, elinewidth=0.9)
        ax.set_xscale("log", base=2)
        ax.set_xticks([27, 32, 64, 128, 256])
        ax.set_xticklabels([27, 32, 64, 128, 256])
        ax.set_yscale("log")
        ax.set_xlabel("Allowlist size (N)")
        ax.set_title(f"{'Hit' if path == 'hit' else 'Miss'} path")
        if ax is axes[0]:
            ax.set_ylabel("Cycles per lookup (log scale)")
        ax.legend(loc="best", frameon=True, framealpha=0.9)

    plt.tight_layout()
    out = out_dir / "fig_trackA_micro.png"
    fig.savefig(out); plt.close(fig)
    print(f"  ✓ {out.name}")


# ---------------------------------------------------------------------------
# Track A — MACRO (unchanged)
# ---------------------------------------------------------------------------
def fig_trackA_macro(macro_csv, out_dir):
    df = pd.read_csv(macro_csv, sep=";")
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df[["strategy", "N"]] = df["component"].str.split("-", expand=True)
    df["N"] = df["N"].astype(int)

    pivot = df.pivot_table(index=["strategy", "N", "attack", "run"],
                           columns="metric", values="value",
                           aggfunc="first").reset_index()
    pivot["cycles_per_frame"] = pivot["cycles"] / pivot["rx_total"].replace(0, np.nan)
    pivot = pivot.dropna(subset=["cycles_per_frame"])

    attacks = ["dos-py", "fuzzing", "legit-flood"]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2), sharey=False)

    for ax, atk in zip(axes, attacks):
        sub = pivot[pivot["attack"] == atk]
        strategies = ["linear", "direct"]
        Ns = [27, 256]
        x = np.arange(len(Ns))
        width = 0.38

        for i, strat in enumerate(strategies):
            means, errs = [], []
            for N in Ns:
                vals = sub[(sub["strategy"] == strat) & (sub["N"] == N)]["cycles_per_frame"].values
                m, ci = bootstrap_ci(vals)
                means.append(m); errs.append(ci)
            offset = (-1 if i == 0 else 1) * width / 2
            ax.bar(x + offset, means, width=width, yerr=errs,
                   color=COLORS[strat], label=strat.capitalize(),
                   capsize=3, edgecolor="white",
                   error_kw={"elinewidth": 0.9})
            for j, (m, ci) in enumerate(zip(means, errs)):
                ax.text(j + offset, m + ci, f"{m:.0f}",
                        ha="center", va="bottom", fontsize=8, color="#444444")

        ax.set_xticks(x)
        ax.set_xticklabels([f"N={n}" for n in Ns])
        ax.set_title(ATTACK_LABELS.get(atk, atk))
        if ax is axes[0]:
            ax.set_ylabel("Cycles per frame")
        ax.legend(loc="upper left", frameon=True, framealpha=0.9)
        ax.set_ylim(0, ax.get_ylim()[1] * 1.18)

    plt.tight_layout()
    out = out_dir / "fig_trackA_macro.png"
    fig.savefig(out); plt.close(fig)
    print(f"  ✓ {out.name}")


# ---------------------------------------------------------------------------
# Track B — SENDER (unchanged)
# ---------------------------------------------------------------------------
def fig_trackB_sender(micro_csv, out_dir):
    df = pd.read_csv(micro_csv)
    df = df[df["op"].isin(["protect", "verify"])].copy()
    df["cycles_per_op"] = pd.to_numeric(df["cycles_per_op"], errors="coerce")
    df = df[df["plain"].isin([4, 20, 36, 52])].copy()

    fig, ax = plt.subplots(figsize=(8, 4.6))

    fit_info = []
    for op in ["protect", "verify"]:
        sub = df[df["op"] == op]
        g = sub.groupby("blocks")["cycles_per_op"]
        xs = sorted(g.groups.keys())
        ys, errs = [], []
        for x in xs:
            m, ci = bootstrap_ci(g.get_group(x).values)
            ys.append(m); errs.append(ci)
        ax.errorbar(xs, ys, yerr=errs,
                    marker="o", markersize=7, capsize=3,
                    color=COLORS[op], label=op.capitalize(),
                    linewidth=1.6, elinewidth=0.9)
        coef = np.polyfit(xs, ys, 1)
        line_x = np.array([0.8, max(xs) + 0.4])
        line_y = np.polyval(coef, line_x)
        ax.plot(line_x, line_y, "--", color=COLORS[op], alpha=0.55, linewidth=1.0)
        yhat = np.polyval(coef, xs)
        ss_res = np.sum((np.array(ys) - yhat) ** 2)
        ss_tot = np.sum((np.array(ys) - np.mean(ys)) ** 2)
        r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 1.0
        fit_info.append((op.capitalize(), coef[1], coef[0], r2))

    fit_text = "\n".join(
        f"{name}: $c_0={c0:.0f}$, $c_1={c1:.0f}$ cyc/block ($R^2={r2:.4f}$)"
        for name, c0, c1, r2 in fit_info
    )
    ax.text(0.03, 0.97, fit_text,
            transform=ax.transAxes, fontsize=9,
            va="top", ha="left",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="white",
                      edgecolor="#888888", linewidth=0.7))

    ax.set_xticks([1, 2, 3, 4])
    ax.set_xticklabels(["1 (4 B)", "2 (20 B)", "3 (36 B)", "4 (52 B)"])
    ax.set_xlabel("AES-128 blocks (payload)")
    ax.set_ylabel("Cycles per operation")
    ax.set_xlim(0.6, 4.4)
    ax.legend(loc="lower right", frameon=True, framealpha=0.9)

    plt.tight_layout()
    out = out_dir / "fig_trackB_sender.png"
    fig.savefig(out); plt.close(fig)
    print(f"  ✓ {out.name}")


# ---------------------------------------------------------------------------
# Track B — GATEWAY COMBINED (heritage + well-formed adversary)
# ---------------------------------------------------------------------------
def fig_trackB_gateway(macro_csv, spoofwf_csv, out_dir):
    # Heritage data (5 inherited vectors, scenario 2 vs 3)
    df_h = pd.read_csv(macro_csv, sep=";")
    df_h["value"] = pd.to_numeric(df_h["value"], errors="coerce")
    ph = df_h.pivot_table(index=["scenario", "component", "attack", "run"],
                          columns="metric", values="value",
                          aggfunc="first").reset_index()
    ph["cycles_per_frame"] = ph["cycles"] / ph["rx_total"].replace(0, np.nan)
    ph = ph.dropna(subset=["cycles_per_frame"])

    attacks = ["dos-py", "dos-cangen", "fuzzing", "replay", "spoofing"]
    fw_means, fw_errs, sc_means, sc_errs = [], [], [], []
    for atk in attacks:
        fw = ph[(ph["scenario"] == "cen2") & (ph["attack"] == atk)]["cycles_per_frame"].values
        sc = ph[(ph["scenario"] == "cen3") & (ph["attack"] == atk)]["cycles_per_frame"].values
        m1, c1 = bootstrap_ci(fw)
        m2, c2 = bootstrap_ci(sc)
        fw_means.append(m1); fw_errs.append(c1)
        sc_means.append(m2); sc_errs.append(c2)

    # Well-formed adversary data
    df_sw = pd.read_csv(spoofwf_csv, sep=";")
    df_sw["value"] = pd.to_numeric(df_sw["value"], errors="coerce")
    psw = df_sw.pivot_table(index=["scenario", "component", "attack", "run"],
                            columns="metric", values="value",
                            aggfunc="first").reset_index()
    psw["cycles_per_frame"] = psw["cycles"] / psw["rx_total"].replace(0, np.nan)
    psw = psw.dropna(subset=["cycles_per_frame"])

    hit = psw[psw["component"] == "hit"]["cycles_per_frame"].values
    miss = psw[psw["component"] == "miss"]["cycles_per_frame"].values
    hit_m, hit_c = bootstrap_ci(hit)
    miss_m, miss_c = bootstrap_ci(miss)

    # Combined figure with two panels
    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(13, 4.6),
        gridspec_kw={"width_ratios": [3, 1]},
    )

    # ---- Panel 1: five inherited vectors ----
    x = np.arange(len(attacks))
    width = 0.38
    ax1.bar(x - width / 2, fw_means, width=width, yerr=fw_errs,
            color=COLORS["firewall"], label="Scenario 2 — Firewall",
            capsize=3, edgecolor="white",
            error_kw={"elinewidth": 0.9})
    ax1.bar(x + width / 2, sc_means, width=width, yerr=sc_errs,
            color=COLORS["secoc"], label="Scenario 3 — SecOC gateway",
            capsize=3, edgecolor="white",
            error_kw={"elinewidth": 0.9})

    for i, atk in enumerate(attacks):
        if fw_means[i] > 0:
            r = sc_means[i] / fw_means[i]
            ymax = max(fw_means[i] + fw_errs[i], sc_means[i] + sc_errs[i])
            ax1.text(i, ymax * 1.04, f"×{r:.2f}",
                     ha="center", va="bottom", fontsize=9,
                     color="#444444", fontweight="bold")

    ax1.set_xticks(x)
    ax1.set_xticklabels([ATTACK_LABELS.get(a, a) for a in attacks],
                        rotation=20, ha="right")
    ax1.set_ylabel("Cycles per frame")
    ax1.set_title("(a) Five inherited vectors")
    ax1.legend(loc="upper right", frameon=True, framealpha=0.9)
    ax1.set_ylim(0, ax1.get_ylim()[1] * 1.20)

    # ---- Panel 2: well-formed adversary ----
    labels = ["Spoof-WF (miss)\nrejected at ID",
              "Spoof-WF (hit)\nMAC verified"]
    positions = [0, 1]
    ax2.bar(positions,
            [miss_m, hit_m],
            yerr=[miss_c, hit_c],
            width=0.55,
            color=[COLORS["spoof-miss"], COLORS["spoof-hit"]],
            capsize=3, edgecolor="white",
            error_kw={"elinewidth": 0.9})
    for i, (m, c) in enumerate(zip([miss_m, hit_m], [miss_c, hit_c])):
        ax2.text(i, m + c * 1.05, f"{m:.0f}",
                 ha="center", va="bottom", fontsize=9, color="#444444")

    delta = hit_m - miss_m
    ax2.annotate(
        f"Δ ≈ {delta:.0f} cyc/frame\n(CMAC cost)",
        xy=(0.5, max(hit_m, miss_m) * 0.55),
        ha="center", va="center", fontsize=9,
        color="#333333",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="white",
                  edgecolor="#888888", linewidth=0.7),
    )

    ax2.set_xticks(positions)
    ax2.set_xticklabels(labels, fontsize=9)
    ax2.set_title("(b) Well-formed adversary")
    ax2.set_ylim(0, max(hit_m + hit_c, miss_m + miss_c) * 1.30)

    plt.tight_layout()
    out = out_dir / "fig_trackB_gateway.png"
    fig.savefig(out); plt.close(fig)
    print(f"  ✓ {out.name}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generates LARS paper figures.")
    ap.add_argument("--repo-root", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=Path("./figures"))
    args = ap.parse_args()

    apply_rcparams()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    root = args.repo_root.resolve()

    a_micro = root / "allowlist-scaling" / "micro.csv"
    a_macro = root / "scenario2-firewall" / "results" / "macro-20260703-172527" / "perf_macro.csv"
    b_micro = root / "scenario3-secoc" / "results-micro" / "20260703-231943-fase2" / "micro.csv"
    b_macro = root / "master-experiment" / "master_results" / "20260704-010156" / "perf_data.csv"
    b_spoof = root / "scenario3-secoc" / "results" / "perf_spoofwf.csv"

    for p in (a_micro, a_macro, b_micro, b_macro, b_spoof):
        if not p.is_file():
            print(f"ERROR: file not found: {p}", file=sys.stderr)
            return 1

    print(f"Output dir: {args.out_dir.resolve()}")
    fig_trackA_micro(a_micro, args.out_dir)
    fig_trackA_macro(a_macro, args.out_dir)
    fig_trackB_sender(b_micro, args.out_dir)
    fig_trackB_gateway(b_macro, b_spoof, args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())