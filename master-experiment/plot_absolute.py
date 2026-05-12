# Lê os artefatos produzidos por analyze_absolute.py e parse_gateway_logs.py e
# gera as figuras prontas para o capítulo de Resultados do TCC.
#
# Figuras geradas (PNG para preview e PDF para LaTeX):
#   fig_taskclock.{png,pdf}        Barplot task-clock cen2/cen3 por ataque
#   fig_cycles_per_frame.{png,pdf} Barplot custo normalizado (sem replay)
#   fig_cen3_decomposition.{png,pdf} Stacked-bar gateway+sender em cen3
#   fig_boxplot_taskclock.{png,pdf}  Distribuição (n=20) por ataque

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
# lib.plotting (importado abaixo) faz matplotlib.use("Agg") antes
# de qualquer import de pyplot — então é seguro importar plt aqui depois.

# Configuração de estilo + paleta + labels — fonte única em lib.plotting.
# (importar lib.plotting ANTES de pyplot — ele faz matplotlib.use("Agg"))
from lib.plotting import (
    apply_rcparams,
    COLORS_ABSOLUTE as COLORS,
    ATTACK_LABELS,
    SCENARIO_LABELS_ABSOLUTE as SCENARIO_LABELS,
    grouped_bar as _grouped_bar_lib,
)
import matplotlib.pyplot as plt  # noqa: E402 — após lib.plotting

apply_rcparams()
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.constants import ATTACK_ORDER
SCENARIO_ORDER = ["cen2/gateway", "cen3/gateway", "cen3/sender", "cen3/total"]


# Helpers de carregamento
def load_absolute(master: Path) -> pd.DataFrame:
    p = master / "absolute_cost.csv"
    if not p.is_file():
        raise FileNotFoundError(f"{p} não existe — rode analyze_absolute.py antes.")
    df = pd.read_csv(p)
    df["sc"] = df["scenario"] + "/" + df["component"]
    return df


def load_normalized(master: Path) -> pd.DataFrame:
    p = master / "normalized_cost.csv"
    if not p.is_file():
        raise FileNotFoundError(f"{p} não existe — rode analyze_absolute.py antes.")
    df = pd.read_csv(p)
    df["sc"] = df["scenario"] + "/" + df["component"]
    return df


from lib.perf_io import load_perf_csv


def load_perf(master: Path) -> pd.DataFrame:
    p = master / "perf_data.csv"
    if not p.is_file():
        raise FileNotFoundError(f"{p} não existe.")
    df = load_perf_csv(p)
    df["sc"] = df["scenario"] + "/" + df["component"]
    return df


# Helper: barplot agrupado com IC95 (wrapper sobre lib.plotting.grouped_bar)
def grouped_bar(ax, df_focus, ylabel: str, title: str,
                attack_order=None, sc_order=None, log=False):
    """Wrapper local que injeta paleta + labels específicos deste script."""
    _grouped_bar_lib(ax, df_focus, ylabel=ylabel, title=title,
                     attack_order=attack_order, sc_order=sc_order, log=log,
                     colors_map=COLORS, scenario_labels=SCENARIO_LABELS,
                     attack_labels=ATTACK_LABELS)


# Figura 1: task-clock absoluto cen2 vs cen3 por ataque
def fig_taskclock(absolute: pd.DataFrame, out_dir: Path) -> None:
    df = absolute[absolute.metric == "task-clock"].copy()
    if df.empty:
        return
    fig, ax = plt.subplots(figsize=(10, 5.0))
    grouped_bar(ax, df, ylabel="Tempo de CPU (ms, escala log)",
                title="Custo absoluto da camada de segurança "
                      "(task-clock, μ ± IC$_{95}$, n=20)",
                attack_order=ATTACK_ORDER,
                sc_order=SCENARIO_ORDER, log=True)
    ax.text(0.01, -0.18,
            "$^{*}$ replay: gateway permanece ativo $>$30 s "
            "(captura+replay), enquanto perf mede 30 s.",
            transform=ax.transAxes, fontsize=8, color="#555555")
    plt.tight_layout()
    fig.savefig(out_dir / "fig_taskclock.png")
    fig.savefig(out_dir / "fig_taskclock.pdf")
    plt.close(fig)


# Figura 2: cycles/frame normalizado — APENAS gateways (cen2 vs cen3)
# O sender é deliberadamente excluído desta figura: ele autentica um número
# constante de frames legítimos (~2100 / 30 s) independentemente do ataque,
# então normalizá-lo pelo `rx_total` do gateway (que varia 100× entre
# DoS e fuzzing) produz números enganosos. O custo absoluto do sender é
# exposto na figura de decomposição (fig_cen3_decomposition).
def fig_cycles_per_frame(norm: pd.DataFrame, out_dir: Path) -> None:
    df = norm[(norm.metric == "cycles")
              & (norm.attack != "replay")
              & (norm.component == "gateway")].copy()
    if df.empty:
        return
    attacks = [a for a in ATTACK_ORDER if a != "replay"]
    sc_order = ["cen2/gateway", "cen3/gateway"]
    fig, ax = plt.subplots(figsize=(8.5, 4.6))
    grouped_bar(ax, df, ylabel="Ciclos por frame recebido (cycles/frame)",
                title="Custo do gateway por frame recebido — "
                      "Firewall vs SecOC (μ ± IC$_{95}$, n=20)",
                attack_order=attacks, sc_order=sc_order, log=False)

    # Anota razão cen3/cen2 acima de cada par para facilitar a leitura
    for i, atk in enumerate(attacks):
        c2 = df[(df.attack == atk) & (df.sc == "cen2/gateway")]
        c3 = df[(df.attack == atk) & (df.sc == "cen3/gateway")]
        if c2.empty or c3.empty:
            continue
        ratio = float(c3["mean"].iloc[0]) / float(c2["mean"].iloc[0])
        # Posição: acima da barra mais alta
        ymax = max(float(c2["mean"].iloc[0]) + float(c2["ci95_half"].iloc[0]),
                   float(c3["mean"].iloc[0]) + float(c3["ci95_half"].iloc[0]))
        ax.text(i, ymax * 1.05, f"×{ratio:.2f}",
                ha="center", va="bottom", fontsize=9,
                color="#444444", fontweight="bold")

    ax.text(0.99, -0.18,
            "Razão cen3/cen2 acima de cada par. Replay omitido (caveat de janela).",
            transform=ax.transAxes, fontsize=8, color="#555555",
            ha="right")
    plt.tight_layout()
    fig.savefig(out_dir / "fig_cycles_per_frame.png")
    fig.savefig(out_dir / "fig_cycles_per_frame.pdf")
    plt.close(fig)


# Figura 3: decomposição do cenário 3 — grouped-bar (gw e sender lado a lado)
# Em DOIS PAINÉIS para evitar distorção:
#    (a) DoS-py / DoS-cangen   — escala alta (10³–10⁴ ms)
#    (b) Fuzzing / Spoofing / Replay — escala baixa (10²–10³ ms)
def fig_cen3_decomposition(absolute: pd.DataFrame, out_dir: Path) -> None:
    df = absolute[(absolute.metric == "task-clock") & (absolute.scenario == "cen3")].copy()
    if df.empty:
        return

    groups = [
        ("Carga alta", ["dos-py", "dos-cangen"]),
        ("Carga baixa", ["fuzzing", "spoofing", "replay"]),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.6),
                             gridspec_kw={"width_ratios": [2, 3]})
    for ax, (title, attacks) in zip(axes, groups):
        n = len(attacks)
        x = np.arange(n)
        width = 0.38
        gw_means, sd_means = [], []
        gw_err, sd_err = [], []
        for atk in attacks:
            gw = df[(df.attack == atk) & (df.component == "gateway")]
            sd = df[(df.attack == atk) & (df.component == "sender")]
            gw_means.append(float(gw["mean"].iloc[0]) if not gw.empty else 0.0)
            sd_means.append(float(sd["mean"].iloc[0]) if not sd.empty else 0.0)
            gw_err.append(float(gw["ci95_half"].iloc[0]) if not gw.empty else 0.0)
            sd_err.append(float(sd["ci95_half"].iloc[0]) if not sd.empty else 0.0)

        ax.bar(x - width / 2, gw_means, width=width, yerr=gw_err,
               color=COLORS["cen3/gateway"],
               label="SecOC gateway (verifica MAC + FV)",
               capsize=3, edgecolor="white",
               error_kw={"elinewidth": 0.9})
        ax.bar(x + width / 2, sd_means, width=width, yerr=sd_err,
               color=COLORS["cen3/sender"],
               label="SecOC sender (gera MAC + atualiza FV)",
               capsize=3, edgecolor="white",
               error_kw={"elinewidth": 0.9})

        # Anota proporção do sender / total
        for i, atk in enumerate(attacks):
            total = gw_means[i] + sd_means[i]
            if total > 0:
                pct = sd_means[i] / total * 100.0
                ymax = max(gw_means[i] + gw_err[i], sd_means[i] + sd_err[i])
                ax.text(i, ymax * 1.03,
                        f"sender = {pct:.0f}%",
                        ha="center", va="bottom", fontsize=8, color="#333333")

        ax.set_xticks(x)
        ax.set_xticklabels([ATTACK_LABELS.get(a, a) for a in attacks])
        ax.set_title(title)
        ax.set_ylabel("Tempo de CPU (ms)")
        ax.legend(loc="upper right", fontsize=9)

    fig.suptitle("Cenário 3 — decomposição do custo do SecOC "
                 "(task-clock, μ ± IC$_{95}$, n=20)",
                 y=1.02, fontsize=12)
    plt.tight_layout()
    fig.savefig(out_dir / "fig_cen3_decomposition.png")
    fig.savefig(out_dir / "fig_cen3_decomposition.pdf")
    plt.close(fig)


# Figura 4: boxplot da distribuição (n=20) por ataque, task-clock
def fig_boxplot(perf: pd.DataFrame, out_dir: Path) -> None:
    df = perf[(perf.metric == "task-clock") & (perf.scenario != "baseline")].copy()
    if df.empty:
        return

    fig, axes = plt.subplots(1, len(ATTACK_ORDER), figsize=(13.5, 4.0),
                             sharey=False)
    for ax, atk in zip(axes, ATTACK_ORDER):
        sub = df[df.attack == atk]
        groups, labels, colors = [], [], []
        for sc in SCENARIO_ORDER[:3]:  # gw, gw, sender (sem total — não está em perf)
            ssub = sub[sub.sc == sc]
            if ssub.empty:
                continue
            groups.append(ssub["value"].values)
            labels.append(SCENARIO_LABELS[sc].split(" — ")[1])
            colors.append(COLORS[sc])
        if not groups:
            continue
        bp = ax.boxplot(groups, tick_labels=labels, patch_artist=True,
                        widths=0.6, showfliers=True,
                        medianprops={"color": "black", "lw": 1.4})
        for patch, color in zip(bp["boxes"], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.65)
        ax.set_title(ATTACK_LABELS.get(atk, atk))
        ax.set_yscale("log")
        ax.tick_params(axis="x", rotation=30)
        if ax is axes[0]:
            ax.set_ylabel("Tempo de CPU (ms, escala log)")
    fig.suptitle("Distribuição do task-clock por (cenário, ataque) — n=20 rodadas",
                 y=1.02, fontsize=12)
    plt.tight_layout()
    fig.savefig(out_dir / "fig_boxplot_taskclock.png")
    fig.savefig(out_dir / "fig_boxplot_taskclock.pdf")
    plt.close(fig)


# Main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Gera figuras a partir dos CSVs do analyze_absolute.py."
    )
    ap.add_argument("--master-dir", type=Path, required=True,
                    help="Diretório resultados/<timestamp>/")
    args = ap.parse_args()

    master = args.master_dir.resolve()
    out_dir = master / "figuras"
    out_dir.mkdir(exist_ok=True)

    absolute = load_absolute(master)
    normalized = load_normalized(master)
    perf = load_perf(master)

    print(f"  Output dir: {out_dir}")
    fig_taskclock(absolute, out_dir)
    print("  ✓ fig_taskclock.{png,pdf}")
    fig_cycles_per_frame(normalized, out_dir)
    print("  ✓ fig_cycles_per_frame.{png,pdf}")
    fig_cen3_decomposition(absolute, out_dir)
    print("  ✓ fig_cen3_decomposition.{png,pdf}")
    fig_boxplot(perf, out_dir)
    print("  ✓ fig_boxplot_taskclock.{png,pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
