# O `analyze_absolute.py` reporta custo absoluto da camada de segurança.
#
# Esta análise usa a campanha SYSTEM-WIDE, em que `perf stat -a` observa o 
# sistema todo nos três cenários. 
#
#     overhead_pct(scenario, attack, metric) =
#         100 * (μ_scenario_system - μ_baseline_system) / μ_baseline_system
#
# Estatística
# -----------
# Para cada (cenário, ataque, métrica): n, μ, σ, CV%, IC95 via t de Student.
# Para o overhead, propagamos o erro pelo método delta:
#
#     σ(X/Y) ≈ |X/Y| · sqrt((σ_X/X)² + (σ_Y/Y)²)
#
# (assumindo X e Y independentes — válido aqui, baseline e cen são corridas
# distintas com cooldown). O IC95 do overhead é então t(n-1) · σ_overhead.

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from lib.stats import t_value, aggregate_groupby

# Configuração
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.constants import (
    ATTACK_ORDER,
    PERF_METRICS_FOCUS_SW as PERF_METRICS_FOCUS,
)


# Carregamento e Agregação
from lib.perf_io import load_perf_csv


def load_perf(master: Path) -> pd.DataFrame:
    """Lê perf_data.csv e filtra só linhas system-wide (component=system)."""
    p = master / "perf_data.csv"
    if not p.is_file():
        raise FileNotFoundError(f"{p} não encontrado.")
    df = load_perf_csv(p, component_filter="system")
    if df.empty:
        raise ValueError(
            "Nenhuma linha com component='system' em perf_data.csv. "
            "Você está apontando para a campanha process-attached em vez "
            "da system-wide?"
        )
    return df


def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    """Por (scenario, attack, metric, unit) → n, mean, std, CV%, IC95.
    Wrapper de aggregate_groupby — não arredonda (caller faz .round(3))."""
    return aggregate_groupby(
        df, ["scenario", "attack", "metric"],
        value_col="value", keep_unit=True,
    )


# Cálculo do overhead com propagação de erro
def overhead_table(stats: pd.DataFrame,
                   baseline_key: str = "baseline") -> pd.DataFrame:
    """
    Computa overhead % vs baseline-system para cada (scenario != baseline,
    attack, metric). Propaga IC95 pelo método delta.

    σ(X/Y) ≈ |X/Y| · sqrt((σ_X/X)² + (σ_Y/Y)²)

    Usamos n_min entre as duas amostras como graus de liberdade (Welch
    aproximado conservador) para o t crítico.
    """
    rows = []
    base = stats[stats.scenario == baseline_key]
    for (sc, atk, met, unit), grp in stats.groupby(
        ["scenario", "attack", "metric", "unit"]
    ):
        if sc == baseline_key:
            continue
        b = base[(base.attack == atk) & (base.metric == met)]
        if b.empty:
            continue
        muX = float(grp["mean"].iloc[0])
        sX  = float(grp["std"].iloc[0])
        nX  = int(grp["n"].iloc[0])
        muY = float(b["mean"].iloc[0])
        sY  = float(b["std"].iloc[0])
        nY  = int(b["n"].iloc[0])

        if muY == 0: 
            continue

        ratio = muX / muY
        ov_pct = (ratio - 1.0) * 100.0

        # Propagação delta: σ_ratio = |ratio| · sqrt(CV_X² + CV_Y²) 
        cvX2 = (sX / muX) ** 2 if muX else 0.0
        cvY2 = (sY / muY) ** 2 if muY else 0.0
        sigma_ratio = abs(ratio) * math.sqrt(cvX2 + cvY2)
        # IC95 usa t com df = min(nX, nY) - 1 (conservador)
        df_min = min(nX, nY) - 1
        # σ da média do ratio: dividimos por sqrt(n) onde n = min(nX,nY)
        # (ainda conservador, dado que tratamos como amostra única)
        n_eff = min(nX, nY)
        sigma_mean_ratio = sigma_ratio / math.sqrt(n_eff) if n_eff > 0 else 0.0
        ci_half_pct = t_value(df_min) * sigma_mean_ratio * 100.0

        rows.append({
            "scenario": sc, "attack": atk, "metric": met, "unit": unit,
            "mu_baseline": muY, "mu_scenario": muX,
            "overhead_pct": ov_pct,
            "ci95_half_pct": ci_half_pct,
            "ci95_low_pct":  ov_pct - ci_half_pct,
            "ci95_high_pct": ov_pct + ci_half_pct,
            "n_baseline": nY, "n_scenario": nX,
            "cv_baseline_pct": (sY / muY * 100.0) if muY else 0.0,
            "cv_scenario_pct": (sX / muX * 100.0) if muX else 0.0,
        })
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    for c in ("mu_baseline", "mu_scenario",
              "overhead_pct", "ci95_half_pct", "ci95_low_pct", "ci95_high_pct",
              "cv_baseline_pct", "cv_scenario_pct"):
        out[c] = out[c].astype(float).round(3)
    return out


# Pivot wide e LaTeX
def to_wide_overhead(over: pd.DataFrame) -> pd.DataFrame:
    """Linhas = (attack, metric); colunas = cenário; célula = "ov ± ic95"."""
    if over.empty:
        return pd.DataFrame()
    df = over[over.metric.isin(PERF_METRICS_FOCUS)].copy()
    df["cell"] = df.apply(
        lambda r: f"{r['overhead_pct']:+.2f} $\\pm$ {r['ci95_half_pct']:.2f}",
        axis=1,
    )
    pivot = df.pivot_table(index=["attack", "metric"],
                           columns="scenario", values="cell", aggfunc="first")
    # Reordena
    cols = [c for c in ("cen2", "cen3") if c in pivot.columns]
    pivot = pivot[cols]
    # Reordena linhas
    pivot = pivot.reset_index()
    pivot["attack_order"] = pivot["attack"].apply(
        lambda a: ATTACK_ORDER.index(a) if a in ATTACK_ORDER else 999)
    pivot["metric_order"] = pivot["metric"].apply(
        lambda m: PERF_METRICS_FOCUS.index(m) if m in PERF_METRICS_FOCUS else 999)
    pivot = pivot.sort_values(["attack_order", "metric_order"]).drop(
        columns=["attack_order", "metric_order"])
    return pivot


from lib.latex import write_table


def write_latex(table: pd.DataFrame, out_path: Path,
                caption: str, label: str) -> None:
    """Wrapper local — alinhamento 2 cols à esquerda específico desta análise."""
    n = len(table.columns)
    align = "l" * 2 + "r" * (n - 2)
    write_table(table, out_path, caption=caption, label=label, align=align,
                generator_comment="% Gerado por analyze_overhead_sw.py — não editar à mão.")


# Apresentação no console
def print_block(title: str) -> None:
    print()
    print("=" * 68)
    print(f"  {title}")
    print("=" * 68)


def print_absolute(stats: pd.DataFrame) -> None:
    print_block("CUSTO ABSOLUTO SYSTEM-WIDE (μ ± IC95)")
    df = stats[stats.metric.isin(PERF_METRICS_FOCUS)].copy()
    if df.empty:
        print("  (sem dados)")
        return
    for met in PERF_METRICS_FOCUS:
        sub = df[df.metric == met]
        if sub.empty:
            continue
        print(f"\n--- {met} ---")
        for atk in ATTACK_ORDER:
            ssub = sub[sub.attack == atk]
            if ssub.empty:
                continue
            print(f"  • {atk}")
            for _, r in ssub.iterrows():
                print(f"      [{r['scenario']:>9}]  μ = {r['mean']:>16,.2f}  "
                      f"± {r['ci95_half']:>12,.2f}  "
                      f"(CV = {r['cv_pct']:>5.1f}%, n = {int(r['n'])})  "
                      f"{r['unit']}")


def print_overhead(over: pd.DataFrame) -> None:
    print_block("OVERHEAD % vs BASELINE SYSTEM-WIDE (μ ± IC95)")
    if over.empty:
        print("  (sem overhead calculável — verifique baseline)")
        return
    for met in PERF_METRICS_FOCUS:
        sub = over[over.metric == met]
        if sub.empty:
            continue
        print(f"\n--- {met} ---")
        for atk in ATTACK_ORDER:
            ssub = sub[sub.attack == atk]
            if ssub.empty:
                continue
            print(f"  • {atk}")
            for _, r in ssub.iterrows():
                print(f"      [{r['scenario']:>5}]  overhead = "
                      f"{r['overhead_pct']:+8.2f} % "
                      f"± {r['ci95_half_pct']:5.2f} %")


# Main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Análise de overhead da campanha SYSTEM-WIDE (Etapa C)."
    )
    ap.add_argument("--master-dir", type=Path, required=True,
                    help="Diretório resultados-sw/<timestamp>/")
    args = ap.parse_args()

    master = args.master_dir.resolve()
    if not master.is_dir():
        print(f"[ERRO] {master} não é um diretório.", file=sys.stderr)
        return 1

    print_block("ANÁLISE DE OVERHEAD — campanha SYSTEM-WIDE")
    print(f"  master_dir : {master}")

    try:
        df = load_perf(master)
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERRO] {e}", file=sys.stderr)
        return 2

    print(f"  linhas system-wide carregadas: {len(df):,}")

    stats = aggregate(df)
    abs_path = master / "absolute_sw.csv"
    stats.round(3).to_csv(abs_path, index=False)
    print(f"  ✓ {abs_path.name}")

    over = overhead_table(stats)
    over_csv = master / "overhead_sw.csv"
    over.to_csv(over_csv, index=False)
    print(f"  ✓ {over_csv.name}")

    wide = to_wide_overhead(over)
    wide_csv = master / "overhead_sw_wide.csv"
    wide.to_csv(wide_csv, index=False)
    print(f"  ✓ {wide_csv.name}")

    write_latex(
        wide, master / "overhead_sw.tex",
        caption="Overhead percentual vs baseline (campanha SYSTEM-WIDE, "
                "$perf~stat~-a$). Valores como $\\mu \\pm IC_{95}$ "
                "(propagação delta de erro, n=10).",
        label="tab:overhead-sw",
    )
    print(f"  ✓ overhead_sw.tex")

    print_absolute(stats)
    print_overhead(over)

    print()
    print(f"Pasta: {master}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
