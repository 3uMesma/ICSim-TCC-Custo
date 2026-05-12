# Lê a saída produzida por master_run.sh e agrega os dados dos três cenários 
# para facilitar a discussão do TCC:
#
#   summary_all.csv         long-format   (cenário, componente, ataque,
#                                          métrica, n, μ, σ, CV%, IC95)
#   comparison_overhead.csv wide-format   (μ por cenário e overhead %)
#   comparison_overhead.tex tabela LaTeX  (pronta para \input{} no TCC)
#
# Métricas derivadas
# ------------------
# Sobre o tidy frame são calculadas média, desvio amostral, coeficiente de
# variação e intervalo de confiança de 95% via t de Student. O overhead de
# cada cenário de segurança é definido como
#       overhead_pct(scenario, attack, metric) =
#            100 · (μ_scenario − μ_baseline) / μ_baseline
# Quando a métrica é uma contagem absoluta (cycles, instructions, ...), 
# interpretar a razão como custo relativo é direto; para métricas de tempo 
# (task-clock em ms), o overhead corresponde ao alongamento da janela 
# ativa de CPU do componente medido.

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.stats import t_value, aggregate_groupby

# Parsing dos dois formatos — helpers movidos para lib.perf_io
from lib.perf_io import (
    to_float as _to_float,
    norm_metric as _norm_metric,
    parse_baseline_csv,
    parse_perf_native_csv,
)


# Regex para extrair (attack, run) de pastas tipo "dos_run01"
_PAT_ATTACK_RUN = re.compile(r"(?P<attack>[a-zA-Z\-]+)_run(?P<run>\d+)")

# Normalização de nomes de ataque:
# A campanha experimental (master_run.sh + run_scenarioN.sh) padronizou todos
# os scripts no mesmo vocabulário canônico:
#     dos-py | dos-cangen | fuzzing | replay | spoofing
# Esta função existe apenas como ponto único de normalização (lowercase +
# strip) caso futuramente surja outro alias — mantém o pareamento
# baseline ↔ cen2 ↔ cen3 robusto a pequenas variações ortográficas.
def canonical_attack(name: str) -> str:
    return name.strip().lower()


# Walkers — descobrem os arquivos certos em cada cenário
@dataclass
class DataPoint:
    scenario: str
    component: str   # 'process' (baseline), 'gateway', 'sender'
    attack: str
    run: int
    metric: str
    value: float
    unit: str


def _name_to_attack_run(name: str) -> tuple[str, int] | None:
    m = _PAT_ATTACK_RUN.search(name)
    if not m:
        return None
    return m.group("attack"), int(m.group("run"))


def collect_baseline(master_dir: Path) -> list[DataPoint]:
    out: list[DataPoint] = []
    raw_dir = master_dir / "baseline" / "raw"
    if not raw_dir.is_dir():
        print(f"[info] sem pasta baseline/raw em {master_dir}; pulando baseline.")
        return out
    for csv_file in sorted(raw_dir.glob("*.csv")):
        # Filename convention: <attack>_run<NN>.csv
        ar = _name_to_attack_run(csv_file.stem)
        default_attack = ar[0] if ar else None
        for r in parse_baseline_csv(csv_file, default_attack=default_attack):
            out.append(DataPoint(
                scenario="baseline",
                component="process",
                attack=canonical_attack(r["attack"]),
                run=r["run"],
                metric=r["metric"],
                value=r["value"],
                unit=r["unit"],
            ))
    return out


def collect_gateway_scenario(master_dir: Path, scenario: str) -> list[DataPoint]:
    """Para cen2 e cen3: cada rep é uma pasta '<attack>_run<NN>/' contendo
    perf.csv (gateway) e — apenas no cen3 — perf_sender.csv (sender)."""
    out: list[DataPoint] = []
    scen_dir = master_dir / ("cenario2" if scenario == "cen2" else "cenario3")
    if not scen_dir.is_dir():
        print(f"[info] sem pasta {scen_dir.name} em {master_dir}; pulando {scenario}.")
        return out
    for sub in sorted(scen_dir.iterdir()):
        if not sub.is_dir():
            continue
        ar = _name_to_attack_run(sub.name)
        if not ar:
            continue
        attack_raw, run = ar
        attack = canonical_attack(attack_raw)

        # gateway
        perf_csv = sub / "perf.csv"
        if perf_csv.is_file():
            for r in parse_perf_native_csv(perf_csv, attack, run):
                out.append(DataPoint(
                    scenario=scenario, component="gateway",
                    attack=r["attack"], run=r["run"],
                    metric=r["metric"], value=r["value"], unit=r["unit"],
                ))

        # sender (só cen3)
        sender_csv = sub / "perf_sender.csv"
        if sender_csv.is_file():
            for r in parse_perf_native_csv(sender_csv, attack, run):
                out.append(DataPoint(
                    scenario=scenario, component="sender",
                    attack=r["attack"], run=r["run"],
                    metric=r["metric"], value=r["value"], unit=r["unit"],
                ))
    return out


# Estatística agregada
def aggregate(df: pd.DataFrame) -> pd.DataFrame:
    """Agrupa por (scenario, component, attack, metric) e calcula stats.
    Wrapper de aggregate_groupby preservando o shape esperado por
    overhead_table() e print_summary() — round em 3 casas + seleção
    explícita de colunas."""
    if df.empty:
        return df
    stats = aggregate_groupby(
        df,
        ["scenario", "component", "attack", "metric"],
        value_col="value",
        keep_unit=True,
    )
    for c in ("mean", "std", "ci95_half", "ci95_low", "ci95_high", "cv_pct"):
        stats[c] = stats[c].astype(float).round(3)
    return stats[[
        "scenario", "component", "attack", "metric", "unit",
        "n", "mean", "std", "cv_pct", "ci95_half", "ci95_low", "ci95_high",
    ]]


def overhead_table(stats: pd.DataFrame, baseline_key: str = "baseline",
                   metrics_focus: Iterable[str] = (
                       "cycles", "instructions", "task-clock",
                       "cache-misses", "context-switches",
                   )) -> pd.DataFrame:
    """
    Constrói uma tabela wide para discussão do overhead. Linhas =
    (attack, metric); colunas = μ por (cenário, componente) + overhead %
    em relação ao baseline.

    Para o cenário 3 reportamos separadamente gateway e sender e também
    a soma 'cen3-total' (custo SecOC integrado), porque o leitor do TCC
    pode querer ler qualquer das três visões.
    """
    if stats.empty:
        return pd.DataFrame()

    df = stats[stats["metric"].isin(list(metrics_focus))].copy()
    df["key"] = df["scenario"] + "-" + df["component"]

    pivot_mean = df.pivot_table(
        index=["attack", "metric", "unit"],
        columns="key",
        values="mean",
        aggfunc="first",
    )

    # Soma gateway+sender no cenário 3 quando ambos existem.
    if {"cen3-gateway", "cen3-sender"}.issubset(pivot_mean.columns):
        pivot_mean["cen3-total"] = (
            pivot_mean.get("cen3-gateway", 0).fillna(0)
            + pivot_mean.get("cen3-sender", 0).fillna(0)
        )

    base_col = f"{baseline_key}-process"
    if base_col not in pivot_mean.columns:
        # Fallback: pega qualquer coluna baseline-* que exista.
        cands = [c for c in pivot_mean.columns if c.startswith("baseline-")]
        base_col = cands[0] if cands else None

    if base_col is not None:
        for col in list(pivot_mean.columns):
            if col == base_col:
                continue
            ov = (pivot_mean[col] - pivot_mean[base_col]) / pivot_mean[base_col] * 100.0
            pivot_mean[f"overhead%_{col}"] = ov.round(2)

    # Reordena: μ primeiro, overheads depois.
    mean_cols = [c for c in pivot_mean.columns if not c.startswith("overhead%")]
    over_cols = [c for c in pivot_mean.columns if c.startswith("overhead%")]
    pivot_mean = pivot_mean[mean_cols + over_cols]
    return pivot_mean.reset_index()


from lib.latex import write_table, format_cell_scientific


def overhead_to_latex(table: pd.DataFrame, out_path: Path,
                      caption: str = "Overhead percentual por cenário "
                                     "em relação ao baseline (sem segurança).",
                      label: str = "tab:overhead-can-security") -> None:
    """Gera uma tabela LaTeX com booktabs"""
    if table.empty:
        out_path.write_text("% (tabela vazia — sem dados)\n", encoding="utf-8")
        return
    n_cols = len(table.columns)
    align = "l" * 3 + "r" * (n_cols - 3)  # attack/metric/unit à esquerda
    write_table(
        table, out_path,
        caption=caption, label=label, align=align,
        generator_comment=("% Tabela gerada automaticamente por "
                           "analyze_all.py — não editar à mão."),
        cell_formatter=format_cell_scientific,
    )


def print_summary(stats: pd.DataFrame) -> None:
    if stats.empty:
        print("  (nenhum dado coletado)")
        return
    keys = ["scenario", "component", "attack", "metric"]
    stats = stats.sort_values(keys)
    last_scen, last_attack = None, None
    for _, r in stats.iterrows():
        if r["scenario"] != last_scen:
            print(f"\n=== {r['scenario'].upper()} ===")
            last_scen = r["scenario"]
            last_attack = None
        if r["attack"] != last_attack:
            print(f"  -- {r['attack']} --")
            last_attack = r["attack"]
        print(f"    [{r['component']:>7}] {r['metric']:>20} | "
              f"μ={r['mean']:>14,.2f} ± {r['ci95_half']:>10,.2f}  "
              f"(σ={r['std']:>10,.2f}, CV={r['cv_pct']:>5.1f}%, n={int(r['n'])}) "
              f"{r['unit']}")


# Main
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Análise estatística unificada (baseline + cen2 + cen3)."
    )
    parser.add_argument("--master-dir", required=True, type=Path,
                        help="Diretório master_results/<timestamp>/ produzido "
                             "por master_run.sh")
    parser.add_argument("--baseline-key", default="baseline",
                        help="Chave do cenário sem segurança (default: baseline)")
    parser.add_argument("--metrics", default="cycles,instructions,task-clock,"
                                              "cache-misses,context-switches",
                        help="Métricas focadas para a tabela de overhead "
                             "(separadas por vírgula).")
    args = parser.parse_args()

    master = args.master_dir.resolve()
    if not master.is_dir():
        print(f"[ERRO] {master} não é um diretório.", file=sys.stderr)
        return 1

    print(f"\n{'='*68}")
    print(f"  ANÁLISE ESTATÍSTICA UNIFICADA — {master.name}")
    print(f"{'='*68}")

    points: list[DataPoint] = []
    points += collect_baseline(master)
    points += collect_gateway_scenario(master, "cen2")
    points += collect_gateway_scenario(master, "cen3")

    if not points:
        print("[ERRO] nenhum dado encontrado.", file=sys.stderr)
        return 2

    df = pd.DataFrame([p.__dict__ for p in points])

    # Salva dados crus normalizados (tidy) — útil para reanálise futura.
    tidy_path = master / "tidy_data.csv"
    df.to_csv(tidy_path, index=False)
    print(f"  Tidy data : {tidy_path}  ({len(df):,} linhas)")

    stats = aggregate(df)
    summary_path = master / "summary_all.csv"
    stats.to_csv(summary_path, index=False)
    print(f"  Summary   : {summary_path}  ({len(stats):,} linhas)")

    metrics_focus = [m.strip() for m in args.metrics.split(",") if m.strip()]
    overhead = overhead_table(stats, baseline_key=args.baseline_key,
                              metrics_focus=metrics_focus)
    overhead_csv = master / "comparison_overhead.csv"
    overhead.to_csv(overhead_csv, index=False)
    print(f"  Overhead  : {overhead_csv}  ({len(overhead):,} linhas)")

    overhead_tex = master / "comparison_overhead.tex"
    overhead_to_latex(overhead, overhead_tex)
    print(f"  LaTeX     : {overhead_tex}")

    print()
    print_summary(stats)

    print()
    print("Próximos passos para o TCC:")
    print(f"  - \\input{{{overhead_tex.name}}} no capítulo de Resultados")
    print(f"  - usar {summary_path.name} para gerar gráficos no matplotlib")
    print(f"  - usar {tidy_path.name} para análises ad-hoc (boxplot, ANOVA, etc.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
