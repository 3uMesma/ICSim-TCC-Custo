# Configuração visual compartilhada e função de barras agrupadas.
# rcParams aplicados via apply_rcparams() para evitar import side-effects.

from __future__ import annotations

import matplotlib
matplotlib.use("Agg")  # headless — antes de qualquer import de pyplot
import matplotlib.pyplot as plt
import numpy as np


DEFAULT_RCPARAMS = {
    "figure.dpi": 110,
    "savefig.dpi": 200,
    "savefig.bbox": "tight",
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linestyle": "--",
    "legend.frameon": False,
    "legend.fontsize": 10,
}

# Paleta para plot_absolute (chaves no formato "scenario/component").
COLORS_ABSOLUTE = {
    "cen2/gateway":  "#1f77b4",
    "cen3/gateway":  "#ff7f0e",
    "cen3/sender":   "#2ca02c",
    "cen3/total":    "#7f7f7f",
}

# Paleta para plot_latency (chaves no formato "scenario/stage").
COLORS_LATENCY = {
    "cen2/firewall":      "#1f77b4",
    "cen3/secoc_sender":  "#2ca02c",
    "cen3/secoc_gateway": "#ff7f0e",
    "cen3/secoc_total":   "#7f7f7f",
}

ATTACK_LABELS = {
    "dos-py":     "DoS (Python)",
    "dos-cangen": "DoS (cangen)",
    "fuzzing":    "Fuzzing",
    "spoofing":   "Spoofing",
    "replay":     "Replay",
}

# Labels sem asterisco (usado em plot_latency).
ATTACK_LABELS_PLAIN = {
    "dos-py":     "DoS (Python)",
    "dos-cangen": "DoS (cangen)",
    "fuzzing":    "Fuzzing",
    "spoofing":   "Spoofing",
    "replay":     "Replay",
}

SCENARIO_LABELS_ABSOLUTE = {
    "cen2/gateway":  "Cen. 2 — Firewall",
    "cen3/gateway":  "Cen. 3 — SecOC gateway",
    "cen3/sender":   "Cen. 3 — SecOC sender",
    "cen3/total":    "Cen. 3 — total (gw + sender)",
}

STAGE_LABELS_LATENCY = {
    "firewall":       "Cen. 2 — Firewall",
    "secoc_sender":   "Cen. 3 — SecOC sender",
    "secoc_gateway":  "Cen. 3 — SecOC gateway",
    "secoc_total":    "Cen. 3 — SecOC total",
}


def apply_rcparams(extra: dict | None = None) -> None:
    """Aplica DEFAULT_RCPARAMS no plt.rcParams. `extra` sobrescreve."""
    plt.rcParams.update(DEFAULT_RCPARAMS)
    if extra:
        plt.rcParams.update(extra)


def color_for(scenario: str, stage_or_comp: str, *,
              colors_map: dict[str, str]) -> str:
    """Cor pra (cenário, etapa-ou-componente). Fallback cinza-médio."""
    return colors_map.get(f"{scenario}/{stage_or_comp}", "#888888")


def grouped_bar(
    ax,
    df_focus,
    *,
    ylabel: str,
    title: str,
    attack_order=None,
    sc_order=None,
    log: bool = False,
    colors_map: dict[str, str] | None = None,
    scenario_labels: dict[str, str] | None = None,
    attack_labels: dict[str, str] | None = None,
):
    """Barras agrupadas por ataque, com séries dadas por sc_order.

    df_focus precisa ter colunas: attack, sc, mean, ci95_half.
    """
    attacks = attack_order or sorted(df_focus["attack"].unique())
    scs = sc_order or sorted(df_focus["sc"].unique())
    n_groups = len(attacks)
    n_series = len(scs)
    width = 0.8 / max(n_series, 1)
    x = np.arange(n_groups)

    cmap = colors_map or {}
    slbl = scenario_labels or {}
    albl = attack_labels or {}

    for i, sc in enumerate(scs):
        means, errs = [], []
        for atk in attacks:
            row = df_focus[(df_focus["attack"] == atk) & (df_focus["sc"] == sc)]
            if row.empty:
                means.append(np.nan); errs.append(0.0)
            else:
                means.append(float(row["mean"].iloc[0]))
                errs.append(float(row["ci95_half"].iloc[0]))
        offset = (i - (n_series - 1) / 2) * width
        ax.bar(x + offset, means, width=width * 0.95, yerr=errs,
               label=slbl.get(sc, sc),
               color=cmap.get(sc, None),
               capsize=2.5, edgecolor="white", linewidth=0.5,
               error_kw={"elinewidth": 0.9})

    ax.set_xticks(x)
    ax.set_xticklabels([albl.get(a, a) for a in attacks])
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if log:
        ax.set_yscale("log")
    ax.legend(loc="upper right", ncol=1)
