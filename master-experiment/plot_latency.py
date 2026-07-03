# Lê os artefatos produzidos por analyze_latency.py:
#   * latency_per_run.csv    (long format, 1 linha por par de frames)
#   * latency_summary.csv    (agregado por scenario/attack/stage)
#   * jitter_summary.csv     (jitter inter-chegada por cen/atk)
#
# Produz três figuras (PNG + PDF) na pasta figuras-lat/:
#   fig_latency_box.{png,pdf}        Boxplot da latência de encaminhamento
#                                    por (cenário, ataque, etapa)
#   fig_latency_cdf.{png,pdf}        CDF da latência (linha por cenário)
#   fig_latency_p99.{png,pdf}        Barplot do p99 com IC95
#

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from lib.plotting import (
    apply_rcparams,
    ATTACK_LABELS_PLAIN as ATTACK_LABELS,
    STAGE_LABELS_LATENCY as STAGE_LABELS,
)
import matplotlib.pyplot as plt

apply_rcparams({"legend.fontsize": 9})

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.constants import ATTACK_ORDER
STAGE_ORDER = ["passthrough", "firewall", "secoc_sender",
               "secoc_gateway", "secoc_total"]

PLOT_STAGES: list[tuple[str, str]] = [
    ("baseline", "passthrough"),
    ("cen2", "firewall"),
    ("cen3", "secoc_sender"),
    ("cen3", "secoc_gateway"),
    ("cen3", "secoc_total"),
]

# Nova paleta de cores (cinza inserido para cobrir o baseline/passthrough)
COLORS = {
    "baseline/passthrough": "#999999", 
    "cen2/firewall": "#874FFF",
    "cen3/secoc_sender": "#66D575",
    "cen3/secoc_gateway": "#F24822",
    "cen3/secoc_total": "#FFC943"
}

def color_for(scenario: str, stage: str) -> str:
    key = f"{scenario}/{stage}"
    return COLORS.get(key, "#000000")

def load_csv(master: Path, fname: str) -> pd.DataFrame:
    p = master / fname
    if not p.is_file():
        return pd.DataFrame()
    return pd.read_csv(p)

def _quality_map(summary: pd.DataFrame) -> dict[tuple[str, str, str], str]:
    out: dict[tuple[str, str, str], str] = {}
    if summary.empty or "quality" not in summary.columns:
        return out
    for _, r in summary.iterrows():
        key = (str(r["scenario"]), str(r["stage"]), str(r["attack"]))
        q = r.get("quality")
        if pd.notna(q):
            out[key] = str(q)
    return out

def _is_plottable(quality_map: dict, sc: str, st: str, atk: str) -> bool:
    return quality_map.get((sc, st, atk), "ok") != "bad"

# Figura 1: boxplot por (etapa, ataque)
def fig_latency_box(per_run: pd.DataFrame, summary: pd.DataFrame,
                    out_dir: Path) -> None:
    if per_run.empty:
        print("  [aviso] latency_per_run.csv vazio — pulando boxplot")
        return

    _ = summary
    attacks = [a for a in ATTACK_ORDER if a in per_run["attack"].unique()]
    stages_present = [(sc, st) for sc, st in PLOT_STAGES
                      if not per_run[(per_run.scenario == sc) &
                                     (per_run.stage == st)].empty]
    if not stages_present:
        print("  [aviso] sem dados de latência válidos")
        return

    n_groups = len(attacks)
    n_series = len(stages_present)
    width = 0.8 / max(n_series, 1)

    fig, ax = plt.subplots(figsize=(10.5, 5.0))
    positions_x = np.arange(n_groups)

    legend_handles = []
    for i, (sc, st) in enumerate(stages_present):
        offset = (i - (n_series - 1) / 2) * width
        data = []
        for atk in attacks:
            sub = per_run[(per_run.scenario == sc) &
                          (per_run.stage == st) &
                          (per_run.attack == atk)]
            data.append(sub["latency_us"].values if not sub.empty
                        else np.array([np.nan]))
        bp = ax.boxplot(data, positions=positions_x + offset,
                        widths=width * 0.85, patch_artist=True,
                        showfliers=False,
                        medianprops={"color": "black", "lw": 1.4})
        c = color_for(sc, st)
        for patch in bp["boxes"]:
            patch.set_facecolor(c)
            patch.set_alpha(0.7)
        legend_handles.append(plt.Rectangle((0, 0), 1, 1, color=c,
                                            label=STAGE_LABELS.get(st, st)))

    ax.set_xticks(positions_x)
    ax.set_xticklabels([ATTACK_LABELS.get(a, a) for a in attacks])
    ax.set_yscale("log")
    ax.set_ylabel("Latência de encaminhamento (µs, escala log)")
    ax.legend(handles=legend_handles, loc="upper right", ncol=2)
    plt.tight_layout()
    fig.savefig(out_dir / "fig_latency_box.png")
    fig.savefig(out_dir / "fig_latency_box.pdf")
    plt.close(fig)
    print("  ✓ fig_latency_box.{png,pdf}")

# Figura 2: CDFs de latência — um arquivo por regime de carga (para usar como subfiguras 4a/4b)
def fig_latency_cdf(per_run: pd.DataFrame, summary: pd.DataFrame,
                    out_dir: Path) -> None:
    if per_run.empty:
        return
    _ = summary

    panels = [
        ("High-load DoS",                 ["dos-py", "dos-cangen"],          "cdf_highload"),
        ("Low-load fuzzing/spoofing/replay", ["fuzzing", "spoofing", "replay"], "cdf_lowload"),
    ]

    for _title, atks, fname in panels:
        fig, ax = plt.subplots(figsize=(5.0, 3.9))
        for sc, st in PLOT_STAGES:
            sub = per_run[(per_run.scenario == sc) &
                          (per_run.stage == st) &
                          (per_run.attack.isin(atks))]
            if sub.empty:
                continue
            v = np.sort(sub["latency_us"].values)
            v = v[v > 0]
            if len(v) == 0:
                continue
            cdf = np.arange(1, len(v) + 1) / len(v)
            ax.plot(v, cdf, color=color_for(sc, st),
                    lw=2.0, alpha=0.9,
                    label=STAGE_LABELS.get(st, f"{sc}/{st}"))
        ax.set_xscale("log")
        ax.set_xlabel("Latency (µs, log scale)", fontsize=13)
        ax.set_ylabel("CDF", fontsize=13)
        ax.set_ylim(0, 1.02)
        ax.tick_params(labelsize=11)
        ax.legend(loc="lower right", fontsize=11)
        plt.tight_layout()
        fig.savefig(out_dir / f"fig_{fname}.png", dpi=300, bbox_inches="tight")
        fig.savefig(out_dir / f"fig_{fname}.pdf", bbox_inches="tight")
        plt.close(fig)
        print(f"  ✓ fig_{fname}.{{png,pdf}}")

# Figura 3: p99 com IC bootstrap simples
def fig_latency_p99(summary: pd.DataFrame, out_dir: Path) -> None:
    if summary.empty:
        return
    attacks = [a for a in ATTACK_ORDER if a in summary["attack"].unique()]

    stages_present = [(sc, st) for sc, st in PLOT_STAGES
                      if not summary[(summary.scenario == sc) &
                                     (summary.stage == st)].empty]

    n_groups = len(attacks)
    n_series = len(stages_present)
    if n_groups == 0 or n_series == 0:
        return
    width = 0.8 / n_series
    x = np.arange(n_groups)

    fig, ax = plt.subplots(figsize=(10.5, 5.0))
    for i, (sc, st) in enumerate(stages_present):
        offset = (i - (n_series - 1) / 2) * width
        means, errs = [], []
        for atk in attacks:
            row = summary[(summary.scenario == sc) &
                          (summary.stage == st) &
                          (summary.attack == atk)]
            if row.empty:
                means.append(np.nan); errs.append(0.0)
                continue
            means.append(float(row["p99_us"].iloc[0]))
            errs.append(float(row["ic95_half_us"].iloc[0]))
        ax.bar(x + offset, means, width=width * 0.92,
               yerr=errs, capsize=2.5,
               color=color_for(sc, st), edgecolor="white",
               label=STAGE_LABELS.get(st, st),
               error_kw={"elinewidth": 0.9})

    ax.set_xticks(x)
    ax.set_xticklabels([ATTACK_LABELS.get(a, a) for a in attacks])
    ax.set_yscale("log")
    ax.set_ylabel("Latência p99 (µs, escala log)")
    ax.legend(loc="upper right", ncol=2)
    ax.text(0.99, -0.18,
            "Erro = IC$_{95}$ da média; informativo, não IC do quantil.",
            transform=ax.transAxes, fontsize=8, color="#555555",
            ha="right")
    plt.tight_layout()
    fig.savefig(out_dir / "fig_latency_p99.png")
    fig.savefig(out_dir / "fig_latency_p99.pdf")
    plt.close(fig)
    print("  ✓ fig_latency_p99.{png,pdf}")

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Gera figuras de latência a partir dos CSVs do "
                    "analyze_latency.py."
    )
    ap.add_argument("--master-dir", type=Path, required=True,
                    help="Diretório resultados-sw/<timestamp>/")
    args = ap.parse_args()

    master = args.master_dir.resolve()
    out_dir = master / "figuras-lat"
    out_dir.mkdir(exist_ok=True)

    per_run = load_csv(master, "latency_per_run.csv")
    summary = load_csv(master, "latency_summary.csv")

    if per_run.empty and summary.empty:
        print("[ERRO] nenhum CSV de latência encontrado. "
              "Rode `analyze_latency.py` antes.", file=sys.stderr)
        return 1

    print(f"  Output dir: {out_dir}")
    fig_latency_box(per_run, summary, out_dir)
    fig_latency_cdf(per_run, summary, out_dir)
    fig_latency_p99(summary, out_dir)
    return 0

if __name__ == "__main__":
    sys.exit(main())