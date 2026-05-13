# Análise do custo absoluto e normalizado da camada de segurança em CAN 
# (cenários 2 e 3)
#
# Este script trata cen2 e cen3 como microbenchmarks da camada de segurança 
# e reporta:
#
#   1) CUSTO ABSOLUTO (μ ± IC95) do gateway/sender, por ataque.
#   2) CUSTO NORMALIZADO por frame: cycles/frame, instructions/frame, etc.
#      Calculado por-rodada (cycles_run / rx_run) e depois agregado
#   3) RAZÃO cen3/cen2 ("custo adicional da autenticação SecOC sobre o
#      firewall"), permitindo discutir o trade-off entre os dois mecanismos.
#
# Para o cenário 3, o custo é decomposto em três linhas:
#   * gateway (verifica MAC + freshness)
#   * sender  (gera MAC e atualiza FV)
#   * total   (soma pareada por rodada, IC95 calculado sobre os totais)
# Uso
#   python3 analyze_absolute.py --master-dir resultados/<timestamp>

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from lib.stats import t_value, aggregate_with_ci as aggregate_stats
from lib.perf_io import load_perf_csv, load_gateway_logs

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.constants import (
    ATTACK_ORDER,
    PERF_METRICS_FOCUS_ABSOLUTE as PERF_METRICS_FOCUS,
    NORMALIZE_EXCLUDE,
    SCENARIO_ORDER_ABSOLUTE as SCENARIO_ORDER,
)


# Construção da tabela absoluta (cen2 e cen3, com decomposição de cen3)
def build_absolute_table(perf: pd.DataFrame) -> pd.DataFrame:
    """
    Para cada (scenario, component, attack, metric), agrega μ ± IC95.
    Adiciona uma linha sintética 'cen3 / total' = gateway + sender (pareado por run).
    """
    # cen2 e cen3 (tudo exceto baseline)
    df = perf[perf.scenario != "baseline"].copy()
    rows = []
    for (sc, comp, atk, met, unit), grp in df.groupby(
        ["scenario", "component", "attack", "metric", "unit"]
    ):
        s = aggregate_stats(grp["value"])
        rows.append({"scenario": sc, "component": comp, "attack": atk,
                     "metric": met, "unit": unit, **s})

    # cen3-total = gateway + sender PAREADO por run (mantém estrutura de erro)
    if not df.empty:
        c3 = df[df.scenario == "cen3"].copy()
        gw = c3[c3.component == "gateway"]
        sd = c3[c3.component == "sender"]
        merged = gw.merge(
            sd, on=["attack", "run", "metric", "unit"],
            suffixes=("_gw", "_sd"), how="inner",
        )
        merged["value_total"] = merged["value_gw"] + merged["value_sd"]
        for (atk, met, unit), grp in merged.groupby(["attack", "metric", "unit"]):
            s = aggregate_stats(grp["value_total"])
            rows.append({"scenario": "cen3", "component": "total", "attack": atk,
                         "metric": met, "unit": unit, **s})

    out = pd.DataFrame(rows)
    if out.empty:
        return out

    # Round para apresentação
    for c in ("mean", "std", "ci95_half", "ci95_low", "ci95_high", "cv_pct"):
        out[c] = out[c].astype(float).round(3)
    return out


# Métricas normalizadas: cycles/frame, instructions/frame, task-clock_ns/frame
def build_normalized_table(perf: pd.DataFrame, gwlogs: pd.DataFrame) -> pd.DataFrame:
    """
    Para cada (cenário, ataque, run), pega rx_total do gateway.log e divide
    cycles/instructions/task-clock pelo número de frames recebidos.

    O cen3-total é calculado pareando gateway e sender no mesmo run e dividindo
    pelo MESMO rx_total (do gateway), pois a "carga ofertada à camada de
    segurança" é o número de frames que entram no gateway — o sender processa
    apenas os legítimos.

    Ataques em NORMALIZE_EXCLUDE são pulados (janela perf ≠ janela gateway)
    """
    # rx_total por (scenario, attack, run, component=gateway)
    rx = (gwlogs[(gwlogs.metric == "rx_total") & (gwlogs.component == "gateway")]
          [["scenario", "attack", "run", "value"]]
          .rename(columns={"value": "rx_total"}))

    rows = []
    for met in ("cycles", "instructions", "task-clock"):
        unit_factor = 1.0
        unit_out = ""
        if met == "task-clock":
            unit_factor = 1e6  # msec → nsec, para obter ns/frame
            unit_out = "ns/frame"
        else:
            unit_out = f"{met}/frame"

        sub = perf[(perf.metric == met) & (perf.scenario != "baseline")]
        if sub.empty:
            continue

        # cen2 + cen3 (gateway, sender) — normalizar por run
        for (sc, comp), g in sub.groupby(["scenario", "component"]):
            merged = g.merge(rx, on=["scenario", "attack", "run"], how="inner")
            if merged.empty:
                continue
            merged = merged[~merged.attack.isin(NORMALIZE_EXCLUDE)]
            merged["per_frame"] = merged["value"] * unit_factor / merged["rx_total"]
            for atk, gg in merged.groupby("attack"):
                s = aggregate_stats(gg["per_frame"])
                rows.append({"scenario": sc, "component": comp, "attack": atk,
                             "metric": met, "unit": unit_out, **s})

        # cen3-total: pareia gateway+sender no mesmo run, divide pelo rx do gateway
        c3 = sub[sub.scenario == "cen3"]
        gw = c3[c3.component == "gateway"]
        sd = c3[c3.component == "sender"]
        merged = gw.merge(sd, on=["attack", "run"], suffixes=("_gw", "_sd"))
        merged = merged.merge(
            rx[rx.scenario == "cen3"][["attack", "run", "rx_total"]],
            on=["attack", "run"], how="inner",
        )
        merged = merged[~merged.attack.isin(NORMALIZE_EXCLUDE)]
        merged["per_frame"] = (merged["value_gw"] + merged["value_sd"]) * unit_factor / merged["rx_total"]
        for atk, gg in merged.groupby("attack"):
            s = aggregate_stats(gg["per_frame"])
            rows.append({"scenario": "cen3", "component": "total", "attack": atk,
                         "metric": met, "unit": unit_out, **s})

    out = pd.DataFrame(rows)
    if out.empty:
        return out
    for c in ("mean", "std", "ci95_half", "ci95_low", "ci95_high", "cv_pct"):
        out[c] = out[c].astype(float).round(4)
    return out


def build_throughput_summary(gwlogs: pd.DataFrame) -> pd.DataFrame:
    """Agrega contadores do gateway/sender (média por ataque)."""
    rows = []
    for (sc, comp, atk, met), grp in gwlogs.groupby(
        ["scenario", "component", "attack", "metric"]
    ):
        s = aggregate_stats(grp["value"])
        rows.append({"scenario": sc, "component": comp, "attack": atk,
                     "metric": met, **s})
    out = pd.DataFrame(rows)
    for c in ("mean", "std", "ci95_half", "ci95_low", "ci95_high", "cv_pct"):
        out[c] = out[c].astype(float).round(2)
    return out


# Saída wide e LaTeX
def to_wide_absolute(table: pd.DataFrame, metric: str,
                     scale: float = 1.0, decimals: int = 0,
                     latex: bool = False) -> pd.DataFrame:
    """
    Pivot wide para uma métrica: linhas = attack, colunas = (scenario, component).
    Cada célula traz μ ± IC95 formatado.

    `scale`    divide os valores antes de formatar (ex.: 1e9 para 10⁹ cycles → G).
    `decimals` controla casas decimais.
    `latex`    se True, usa $\\pm$ em vez de ± (mais robusto em LaTeX).
    """
    if table.empty:
        return pd.DataFrame()
    df = table[table.metric == metric].copy()
    if df.empty:
        return pd.DataFrame()

    sep = r" $\pm$ " if latex else " ± "
    fmt = f",.{decimals}f"

    def _cell(r):
        if math.isnan(r["mean"]):
            return "—"
        m = r["mean"] / scale
        e = r["ci95_half"] / scale
        return f"{m:{fmt}}{sep}{e:{fmt}}"

    df["cell"] = df.apply(_cell, axis=1)
    df["sc"] = df["scenario"] + "/" + df["component"]
    pivot = df.pivot_table(index="attack", columns="sc", values="cell", aggfunc="first")

    # Reordena colunas e linhas
    col_order = []
    for sc, comp in SCENARIO_ORDER:
        key = f"{sc}/{comp}"
        if key in pivot.columns:
            col_order.append(key)
    pivot = pivot[col_order] if col_order else pivot

    row_order = [a for a in ATTACK_ORDER if a in pivot.index]
    if row_order:
        pivot = pivot.loc[row_order]
    return pivot.reset_index()


from lib.latex import write_table as _write_table_helper


def write_latex(table: pd.DataFrame, out_path: Path,
                caption: str, label: str) -> None:
    """Wrapper local — preserva a assinatura usada no main()."""
    _write_table_helper(table, out_path, caption=caption, label=label,
                        generator_comment="% Gerado por analyze_absolute.py")


# Print legível (saída de console)
def print_block(title: str) -> None:
    print()
    print("=" * 68)
    print(f"  {title}")
    print("=" * 68)


def print_absolute(absolute: pd.DataFrame) -> None:
    print_block("CUSTO ABSOLUTO DA CAMADA DE SEGURANÇA (μ ± IC95)")
    if absolute.empty:
        print("  (sem dados)")
        return
    for met in PERF_METRICS_FOCUS:
        sub = absolute[absolute.metric == met]
        if sub.empty:
            continue
        print(f"\n--- {met} ---")
        for atk in ATTACK_ORDER:
            ssub = sub[sub.attack == atk]
            if ssub.empty:
                continue
            print(f"  • {atk}")
            for _, r in ssub.iterrows():
                key = f"{r['scenario']}/{r['component']}"
                print(f"      [{key:>14}]  μ = {r['mean']:>16,.2f}  "
                      f"± {r['ci95_half']:>12,.2f}  "
                      f"(σ = {r['std']:>12,.2f}, CV = {r['cv_pct']:>5.1f}%, "
                      f"n = {int(r['n'])})  {r['unit']}")


def print_normalized(norm: pd.DataFrame) -> None:
    print_block("CUSTO NORMALIZADO POR FRAME RECEBIDO (μ ± IC95)")
    if norm.empty:
        print("  (sem dados)")
        return
    print(f"  Excluídos da normalização (janela perf ≠ janela gateway): "
          f"{', '.join(sorted(NORMALIZE_EXCLUDE))}")
    for met in ("cycles", "instructions", "task-clock"):
        sub = norm[norm.metric == met]
        if sub.empty:
            continue
        unit = sub["unit"].iloc[0]
        print(f"\n--- {met} → {unit} ---")
        for atk in ATTACK_ORDER:
            if atk in NORMALIZE_EXCLUDE:
                continue
            ssub = sub[sub.attack == atk]
            if ssub.empty:
                continue
            print(f"  • {atk}")
            for _, r in ssub.iterrows():
                key = f"{r['scenario']}/{r['component']}"
                print(f"      [{key:>14}]  μ = {r['mean']:>10.4f}  "
                      f"± {r['ci95_half']:>8.4f}  "
                      f"(CV = {r['cv_pct']:>5.1f}%, n = {int(r['n'])})  {unit}")


# Main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Análise do custo absoluto e normalizado da camada de "
                    "segurança em CAN."
    )
    ap.add_argument("--master-dir", type=Path, required=True,
                    help="Diretório resultados/<timestamp>/ contendo "
                         "perf_data.csv e gateway_logs.csv")
    args = ap.parse_args()

    master = args.master_dir.resolve()
    perf_path = master / "perf_data.csv"
    gw_path = master / "gateway_logs.csv"

    if not perf_path.is_file():
        print(f"[ERRO] {perf_path} não encontrado", file=sys.stderr)
        return 1
    if not gw_path.is_file():
        print(f"[ERRO] {gw_path} não encontrado.\n"
              f"        Rode antes:\n"
              f"        python3 parse_gateway_logs.py --master-dir {master}",
              file=sys.stderr)
        return 1

    print_block("ANÁLISE ABSOLUTA + NORMALIZADA — camada de segurança CAN")
    print(f"  perf_data    : {perf_path}")
    print(f"  gateway_logs : {gw_path}")

    # Carrega perf + gateway logs (helpers compartilhados)
    perf = load_perf_csv(perf_path)
    gw = load_gateway_logs(gw_path)

    # ---- Tabela ABSOLUTA ----
    absolute = build_absolute_table(perf)
    abs_csv = master / "absolute_cost.csv"
    absolute.to_csv(abs_csv, index=False)
    print(f"\n  ✓ absolute_cost.csv   ({len(absolute):,} linhas) → {abs_csv}")

    # Versão wide (mais legível) — uma para cada métrica focal
    abs_wide_path = master / "absolute_cost_wide.csv"
    with abs_wide_path.open("w", encoding="utf-8") as f:
        for met in PERF_METRICS_FOCUS:
            wide = to_wide_absolute(absolute, met)
            if wide.empty:
                continue
            f.write(f"# {met}\n")
            wide.to_csv(f, index=False)
            f.write("\n")
    print(f"  ✓ absolute_cost_wide.csv → {abs_wide_path}")

    # LaTeX para cycles, instructions e task-clock — versões legíveis
    write_latex(
        to_wide_absolute(absolute, "cycles", scale=1e9, decimals=2, latex=True),
        master / "absolute_cost_cycles.tex",
        caption="Custo absoluto da camada de segurança em ciclos de CPU "
                "($\\times 10^{9}$, média $\\pm$ IC$_{95}$, n=20). Cenário 3 "
                "decomposto em gateway, sender e total pareado por rodada.",
        label="tab:abs-cycles",
    )
    write_latex(
        to_wide_absolute(absolute, "instructions", scale=1e9, decimals=2, latex=True),
        master / "absolute_cost_instructions.tex",
        caption="Instruções executadas pela camada de segurança "
                "($\\times 10^{9}$, média $\\pm$ IC$_{95}$, n=20).",
        label="tab:abs-instructions",
    )
    write_latex(
        to_wide_absolute(absolute, "task-clock", scale=1.0, decimals=0, latex=True),
        master / "absolute_cost_taskclock.tex",
        caption="Custo absoluto em tempo de CPU "
                "(\\textit{task-clock}, ms, média $\\pm$ IC$_{95}$, n=20).",
        label="tab:abs-taskclock",
    )
    print(f"  ✓ absolute_cost_{{cycles,instructions,taskclock}}.tex")

    # ---- Tabela NORMALIZADA ----
    normalized = build_normalized_table(perf, gw)
    norm_csv = master / "normalized_cost.csv"
    normalized.to_csv(norm_csv, index=False)
    print(f"\n  ✓ normalized_cost.csv ({len(normalized):,} linhas) → {norm_csv}")

    # LaTeX para cycles/frame e instructions/frame
    excluded = sorted(NORMALIZE_EXCLUDE)
    excl_note = ""
    if excluded:
        excl_note = (" Ataques omitidos por incompatibilidade entre janela do "
                     f"\\texttt{{perf}} e do gateway: {', '.join(excluded)}.")
    write_latex(
        to_wide_absolute(normalized, "cycles", scale=1.0, decimals=1, latex=True),
        master / "normalized_cost_cycles.tex",
        caption=("Custo normalizado da camada de segurança em ciclos por frame "
                 "recebido pelo gateway (média $\\pm$ IC$_{95}$, n=20)." +
                 excl_note),
        label="tab:norm-cycles",
    )
    write_latex(
        to_wide_absolute(normalized, "instructions", scale=1.0, decimals=1, latex=True),
        master / "normalized_cost_instructions.tex",
        caption=("Instruções por frame recebido pelo gateway "
                 "(média $\\pm$ IC$_{95}$, n=20)." + excl_note),
        label="tab:norm-instructions",
    )

    # ---- Throughput / contadores brutos ----
    tp = build_throughput_summary(gw)
    tp_path = master / "throughput_summary.csv"
    tp.to_csv(tp_path, index=False)
    print(f"  ✓ throughput_summary.csv → {tp_path}")

    # Tabela LaTeX de carga ofertada ao gateway (rx_total, fwd_total, taxa)
    rx_pivot = (
        tp[(tp["component"] == "gateway") & (tp["metric"] == "rx_total")]
        .set_index(["scenario", "attack"])["mean"]
        .unstack("scenario").reindex(ATTACK_ORDER)
    )
    fwd_pivot = (
        tp[(tp["component"] == "gateway") & (tp["metric"] == "fwd_total")]
        .set_index(["scenario", "attack"])["mean"]
        .unstack("scenario").reindex(ATTACK_ORDER)
    )
    rows = []
    for atk in ATTACK_ORDER:
        if atk not in rx_pivot.index:
            continue
        rx2 = rx_pivot.loc[atk].get("cen2", float("nan"))
        rx3 = rx_pivot.loc[atk].get("cen3", float("nan"))
        fwd2 = fwd_pivot.loc[atk].get("cen2", float("nan"))
        fwd3 = fwd_pivot.loc[atk].get("cen3", float("nan"))
        rows.append({
            "attack": atk,
            "rx_cen2": f"{rx2:,.0f}" if not math.isnan(rx2) else "—",
            "rx_cen3": f"{rx3:,.0f}" if not math.isnan(rx3) else "—",
            "fwd_cen2": f"{fwd2:,.0f}" if not math.isnan(fwd2) else "—",
            "fwd_cen3": f"{fwd3:,.0f}" if not math.isnan(fwd3) else "—",
        })
    tp_table = pd.DataFrame(rows)
    if not tp_table.empty:
        tp_table.columns = ["ataque", "rx (cen2)", "rx (cen3)",
                            "fwd (cen2)", "fwd (cen3)"]
    write_latex(
        tp_table,
        master / "throughput_table.tex",
        caption="Carga oferecida ao gateway: frames recebidos (\\textit{rx}) e "
                "frames liberados/autenticados (\\textit{fwd}) durante a "
                "execução de cada ataque (média de n=20 rodadas, 30\\,s cada).",
        label="tab:throughput",
    )
    print(f"  ✓ throughput_table.tex")

    # ---- Saída humana ----
    print_absolute(absolute)
    print_normalized(normalized)

    print()
    print("Próximos passos:")
    print(f"  - Inspecione absolute_cost_wide.csv (legível em qualquer editor).")
    print(f"  - \\input{{absolute_cost_cycles.tex}} no capítulo de Resultados.")
    print(f"  - Para gráficos: rode plot_absolute.py (próxima etapa).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
