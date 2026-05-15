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


# Construção da tabela absoluta (baseline + cen2 + cen3, com decomposição de cen3)
def build_absolute_table(perf: pd.DataFrame) -> pd.DataFrame:
    """
    Para cada (scenario, component, attack, metric), agrega μ ± IC95.
    Adiciona uma linha sintética 'cen3 / total' = gateway + sender (pareado por run).

    A partir da migração para passthrough no baseline, baseline-passthrough
    entra como mais um componente medido — todos os três cenários têm
    perfil funcional comparável ("ler de socket CAN, decidir, escrever em
    outro socket"), só mudando o que se faz dentro do laço.
    """
    # Inclui baseline-passthrough, cen2-gateway, cen3-gateway, cen3-sender.
    df = perf.copy()
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


# Métricas normalizadas: cycles/frame, instructions/frame, task-clock_ns/frame.
#
# Denominador correto por componente
# ----------------------------------
# A normalização "por frame" só faz sentido quando o numerador (cycles do
# perf) e o denominador (frames processados) descrevem o mesmo objeto. Por
# isso este script usa um denominador DIFERENTE para cada componente:
#
#     baseline/passthrough  →  rx_total do passthrough.log
#                              (frames lidos em vcan0 pelo forwarder)
#     cen2/gateway          →  rx_total do gateway.log do cen2
#                              (frames lidos em vcan0 pelo firewall)
#     cen3/gateway          →  rx_total do gateway.log do cen3
#                              (frames lidos em vcan0 pelo SecOC gateway)
#     cen3/sender           →  read do sender.log
#                              (frames lidos em vcan_trust pelo SecOC sender)
#     cen3/total            →  rx_total do gateway.log do cen3
#                              (carga ofertada à camada de segurança)
#
# O cen3-total é mantido com denominador = gateway.rx_total porque
# responde uma pergunta diferente: "quanto de CPU a camada de segurança
# consome para cada frame que o atacante consegue ofertar?". Essa é a
# métrica de overhead amortizado da camada, complementar (não substitutiva)
# ao custo unitário de gateway e sender em separado.
def build_normalized_table(perf: pd.DataFrame, gwlogs: pd.DataFrame) -> pd.DataFrame:
    """
    Para cada (cenário, ataque, run), divide cycles/instructions/task-clock
    do componente medido pelo número de frames que ESSE componente
    efetivamente processou. Ver tabela de denominadores no header do bloco.

    Ataques em NORMALIZE_EXCLUDE são pulados (janela perf ≠ janela gateway).
    """
    # Denominador por componente.
    # rx_total: usado por passthrough e gateway (frames lidos em vcan0).
    rx = (gwlogs[(gwlogs.metric == "rx_total")
                 & (gwlogs.component.isin({"passthrough", "gateway"}))]
          [["scenario", "component", "attack", "run", "value"]]
          .rename(columns={"value": "rx_total"}))
    # read: usado por sender (frames lidos em vcan_trust).
    sender_read = (gwlogs[(gwlogs.metric == "read")
                          & (gwlogs.component == "sender")]
                   [["scenario", "attack", "run", "value"]]
                   .rename(columns={"value": "sender_read"}))

    def _denominator(scenario: str, component: str) -> pd.DataFrame:
        """Retorna DataFrame [scenario, attack, run, denom] adequado."""
        if component == "sender":
            return (sender_read.assign(component=component)
                    .rename(columns={"sender_read": "denom"})
                    [["scenario", "attack", "run", "denom"]])
        # passthrough ou gateway → rx_total do próprio componente
        sub = rx[(rx.scenario == scenario) & (rx.component == component)]
        return sub.rename(columns={"rx_total": "denom"})[
            ["scenario", "attack", "run", "denom"]
        ]

    rows = []
    for met in ("cycles", "instructions", "task-clock"):
        unit_factor = 1.0
        unit_out = ""
        if met == "task-clock":
            unit_factor = 1e6  # msec → nsec, para obter ns/frame
            unit_out = "ns/frame"
        else:
            unit_out = f"{met}/frame"

        sub = perf[perf.metric == met]
        if sub.empty:
            continue

        # Por (cenário, componente): denominador específico do componente.
        for (sc, comp), g in sub.groupby(["scenario", "component"]):
            denom = _denominator(sc, comp)
            if denom.empty:
                continue
            merged = g.merge(denom, on=["scenario", "attack", "run"], how="inner")
            if merged.empty:
                continue
            merged = merged[~merged.attack.isin(NORMALIZE_EXCLUDE)]
            merged = merged[merged["denom"] > 0]
            if merged.empty:
                continue
            merged["per_frame"] = merged["value"] * unit_factor / merged["denom"]
            for atk, gg in merged.groupby("attack"):
                s = aggregate_stats(gg["per_frame"])
                rows.append({"scenario": sc, "component": comp, "attack": atk,
                             "metric": met, "unit": unit_out, **s})

        # cen3-total: pareia gateway+sender no mesmo run, divide pela carga
        # ofertada à camada (gateway.rx_total).
        c3 = sub[sub.scenario == "cen3"]
        gw = c3[c3.component == "gateway"]
        sd = c3[c3.component == "sender"]
        merged = gw.merge(sd, on=["attack", "run"], suffixes=("_gw", "_sd"))
        c3_rx = rx[(rx.scenario == "cen3") & (rx.component == "gateway")][
            ["attack", "run", "rx_total"]
        ]
        merged = merged.merge(c3_rx, on=["attack", "run"], how="inner")
        merged = merged[~merged.attack.isin(NORMALIZE_EXCLUDE)]
        merged = merged[merged["rx_total"] > 0]
        if not merged.empty:
            merged["per_frame"] = (
                (merged["value_gw"] + merged["value_sd"])
                * unit_factor / merged["rx_total"]
            )
            for atk, gg in merged.groupby("attack"):
                s = aggregate_stats(gg["per_frame"])
                rows.append({"scenario": "cen3", "component": "total",
                             "attack": atk, "metric": met,
                             "unit": unit_out, **s})

    out = pd.DataFrame(rows)
    if out.empty:
        return out
    for c in ("mean", "std", "ci95_half", "ci95_low", "ci95_high", "cv_pct"):
        out[c] = out[c].astype(float).round(4)
    return out


# Evidência do custo de verificação MAC sob ataques que simulam tráfego legítimo
# ------------------------------------------------------------------------------
# Quando o ataque usa IDs fora da allowlist (DoS-py com 0x000, DoS-cangen
# random), o gateway rejeita 99.99% do tráfego no `blocked_id` — antes de
# acionar a verificação criptográfica. Nesse regime, cen2 e cen3 têm custo
# essencialmente idêntico (lookup linear de ID + descarte).
#
# Quando o ataque usa IDs legítimos com payload falsificado (spoofing,
# replay), parte do tráfego PASSA o filtro de ID e somente no cen3 esses
# frames disparam a verificação AES-CMAC + FV. A diferença cen3 − cen2 em
# cycles por frame recebido isola justamente esse trabalho extra.
#
# Esta tabela quantifica:
#   - n_reached_mac      : rx_total − blocked_id ≈ frames que chegaram
#                          ao bloco de verificação criptográfica
#   - delta_cycles_total : (cen3.cycles − cen2.cycles) somado por ataque
#   - cycles_per_mac_check: delta_cycles_total / n_reached_mac
#                           cota empírica do custo unitário do MAC+FV check
def build_mac_overhead_evidence(perf: pd.DataFrame,
                                gwlogs: pd.DataFrame) -> pd.DataFrame:
    """Compara o custo absoluto cen3-gateway vs cen2-gateway por ataque e
    cruza com a contagem de frames que chegaram ao MAC (rx − blocked_id).
    Retorna DataFrame agregado por ataque."""
    # Custo absoluto em cycles agregado por (cenário, ataque) — usa apenas
    # o componente gateway, que é o que existe nos dois cenários.
    cyc = perf[(perf.metric == "cycles")
               & (perf.component == "gateway")].copy()
    if cyc.empty:
        return pd.DataFrame()

    # μ pareado por run; depois agrega por ataque.
    pv = cyc.groupby(["scenario", "attack", "run"])["value"].sum().reset_index()
    pv_wide = pv.pivot_table(index=["attack", "run"], columns="scenario",
                             values="value")
    if not {"cen2", "cen3"}.issubset(pv_wide.columns):
        return pd.DataFrame()
    pv_wide = pv_wide.dropna(subset=["cen2", "cen3"])
    pv_wide["delta"] = pv_wide["cen3"] - pv_wide["cen2"]

    # rx_total e blocked_id por (cenário, ataque, run, gateway)
    counters = gwlogs[(gwlogs.component == "gateway")
                      & (gwlogs.scenario == "cen3")
                      & (gwlogs.metric.isin(["rx_total", "blocked_id"]))]
    counters_wide = counters.pivot_table(
        index=["attack", "run"], columns="metric", values="value")
    if "rx_total" not in counters_wide or "blocked_id" not in counters_wide:
        return pd.DataFrame()
    counters_wide["reached_mac"] = (counters_wide["rx_total"]
                                    - counters_wide["blocked_id"])

    merged = pv_wide.join(counters_wide[["reached_mac"]], how="inner")
    if merged.empty:
        return pd.DataFrame()
    merged = merged[merged["reached_mac"] > 0].copy()
    merged["cycles_per_mac_check"] = (merged["delta"]
                                      / merged["reached_mac"])

    # Agrega por ataque (mean ± IC95 sobre os runs).
    rows = []
    for atk, gg in merged.groupby("attack"):
        s_delta = aggregate_stats(gg["delta"])
        s_per   = aggregate_stats(gg["cycles_per_mac_check"])
        rows.append({
            "attack": atk,
            "n_runs": int(s_delta["n"]),
            "reached_mac_mean": float(gg["reached_mac"].mean()),
            "delta_cycles_mean": float(s_delta["mean"]),
            "delta_cycles_ci95_half": float(s_delta["ci95_half"]),
            "cycles_per_mac_check_mean": float(s_per["mean"]),
            "cycles_per_mac_check_ci95_half": float(s_per["ci95_half"]),
            "cv_pct": float(s_per["cv_pct"]),
        })
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    # Ordena na ordem de ataques + arredonda.
    out["__order"] = out["attack"].map(
        {a: i for i, a in enumerate(ATTACK_ORDER)}).fillna(99)
    out = out.sort_values("__order").drop(columns="__order").reset_index(drop=True)
    for c in ("reached_mac_mean",
              "delta_cycles_mean", "delta_cycles_ci95_half",
              "cycles_per_mac_check_mean", "cycles_per_mac_check_ci95_half",
              "cv_pct"):
        out[c] = out[c].astype(float).round(2)
    return out


# Custo por autenticação SecOC
# ----------------------------
# Métrica dedicada ao cen3/sender: custo de UMA operação de autenticação
# (AES-CMAC + atualização de FV + write). Numerador = cycles totais do
# sender no run; denominador = número de frames efetivamente autenticados
# (campo "authenticated_tx" do sender.log).
#
# Diferente de cycles/frame (que divide por TODOS os frames lidos do
# vcan_trust, incluindo os descartados por ID/LEN), esta métrica isola o
# trabalho criptográfico de fato realizado.
def build_cost_per_auth_table(perf: pd.DataFrame,
                              gwlogs: pd.DataFrame) -> pd.DataFrame:
    """Para cen3/sender, calcula cycles, instructions e task-clock divididos
    por `authenticated_tx` (frames efetivamente autenticados pelo sender).
    Retorna DataFrame com colunas [attack, metric, unit, n, mean, std,
    cv_pct, ci95_half, ci95_low, ci95_high].
    """
    auth = (gwlogs[(gwlogs.metric == "authenticated_tx")
                   & (gwlogs.component == "sender")]
            [["scenario", "attack", "run", "value"]]
            .rename(columns={"value": "auth_tx"}))
    if auth.empty:
        return pd.DataFrame()

    rows = []
    for met in ("cycles", "instructions", "task-clock"):
        if met == "task-clock":
            unit_factor = 1e6
            unit_out = "ns/auth"
        else:
            unit_factor = 1.0
            unit_out = f"{met}/auth"

        sub = perf[(perf.metric == met) & (perf.scenario == "cen3")
                   & (perf.component == "sender")]
        if sub.empty:
            continue
        merged = sub.merge(auth, on=["scenario", "attack", "run"], how="inner")
        merged = merged[~merged.attack.isin(NORMALIZE_EXCLUDE)]
        merged = merged[merged["auth_tx"] > 0]
        if merged.empty:
            continue
        merged["per_auth"] = merged["value"] * unit_factor / merged["auth_tx"]
        for atk, gg in merged.groupby("attack"):
            s = aggregate_stats(gg["per_auth"])
            rows.append({"scenario": "cen3", "component": "sender",
                         "attack": atk, "metric": met,
                         "unit": unit_out, **s})

    out = pd.DataFrame(rows)
    if out.empty:
        return out
    for c in ("mean", "std", "ci95_half", "ci95_low", "ci95_high", "cv_pct"):
        out[c] = out[c].astype(float).round(3)
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
    print_block("CUSTO NORMALIZADO POR FRAME PROCESSADO (μ ± IC95)")
    if norm.empty:
        print("  (sem dados)")
        return
    excluded = sorted(NORMALIZE_EXCLUDE)
    if excluded:
        print(f"  Excluídos da normalização (janela perf ≠ janela gateway): "
              f"{', '.join(excluded)}")
    print("  Denominador por componente:")
    print("    baseline/passthrough → rx_total do passthrough.log")
    print("    cen2/gateway, cen3/gateway → rx_total do gateway.log")
    print("    cen3/sender → read do sender.log (vcan_trust)")
    print("    cen3/total  → rx_total do gateway.log (carga ofertada à camada)")
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
                print(f"      [{key:>22}]  μ = {r['mean']:>10.4f}  "
                      f"± {r['ci95_half']:>8.4f}  "
                      f"(CV = {r['cv_pct']:>5.1f}%, n = {int(r['n'])})  {unit}")


def print_cost_per_auth(cpa: pd.DataFrame) -> None:
    print_block("CUSTO POR AUTENTICAÇÃO SecOC (cen3/sender, μ ± IC95)")
    if cpa.empty:
        print("  (sem dados — verifique se há authenticated_tx em gateway_logs.csv)")
        return
    print("  Denominador: authenticated_tx do sender.log")
    print("  Isola o custo unitário de uma operação SecOC (AES-CMAC + FV + write).")
    for met in ("cycles", "instructions", "task-clock"):
        sub = cpa[cpa.metric == met]
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
            for _, r in ssub.iterrows():
                print(f"  • {atk:>11}  μ = {r['mean']:>12,.1f}  "
                      f"± {r['ci95_half']:>10,.1f}  "
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
    norm_caption_note = (
        " Denominador é específico por componente: passthrough e gateway "
        "dividem pelo \\texttt{rx\\_total} do próprio binário; o sender "
        "divide pelos frames lidos em \\texttt{vcan\\_trust}; cen3/total "
        "divide pelo \\texttt{rx\\_total} do gateway (carga ofertada à "
        "camada de segurança).")
    write_latex(
        to_wide_absolute(normalized, "cycles", scale=1.0, decimals=1, latex=True),
        master / "normalized_cost_cycles.tex",
        caption=("Custo normalizado da camada de segurança em ciclos por "
                 "frame processado pelo componente (média $\\pm$ IC$_{95}$, "
                 "n=20)." + norm_caption_note + excl_note),
        label="tab:norm-cycles",
    )
    write_latex(
        to_wide_absolute(normalized, "instructions", scale=1.0, decimals=1, latex=True),
        master / "normalized_cost_instructions.tex",
        caption=("Instruções por frame processado pelo componente "
                 "(média $\\pm$ IC$_{95}$, n=20)." +
                 norm_caption_note + excl_note),
        label="tab:norm-instructions",
    )

    # ---- Evidência do custo de verificação MAC (cen3 vs cen2 gateway) ----
    mac_ev = build_mac_overhead_evidence(perf, gw)
    if not mac_ev.empty:
        mac_csv = master / "mac_overhead_evidence.csv"
        mac_ev.to_csv(mac_csv, index=False)
        print(f"\n  ✓ mac_overhead_evidence.csv → {mac_csv}")

        # Tabela LaTeX legível. Coluna principal: cycles_per_mac_check.
        # Para legibilidade, formata reached_mac em milhares (×10³).
        tex_rows = []
        for _, r in mac_ev.iterrows():
            tex_rows.append({
                "ataque": r["attack"],
                r"frames p/ MAC ($\times 10^3$)":
                    f"{r['reached_mac_mean']/1000:,.1f}",
                r"$\Delta$ ciclos totais ($\times 10^9$)":
                    f"{r['delta_cycles_mean']/1e9:,.2f} $\\pm$ "
                    f"{r['delta_cycles_ci95_half']/1e9:,.2f}",
                "ciclos / verificação MAC":
                    f"{r['cycles_per_mac_check_mean']:,.1f} $\\pm$ "
                    f"{r['cycles_per_mac_check_ci95_half']:,.1f}",
            })
        tex_df = pd.DataFrame(tex_rows)
        write_latex(
            tex_df,
            master / "mac_overhead_evidence.tex",
            caption=("Evidência do custo de verificação MAC sob ataques que "
                     "simulam tráfego legítimo. $\\Delta$ ciclos = "
                     "(cen3-gateway $-$ cen2-gateway) acumulado nos n=20 "
                     "runs; ``frames p/ MAC'' = \\texttt{rx\\_total} "
                     "$-$ \\texttt{blocked\\_id} no cen3 (frames que "
                     "passaram o filtro de ID e dispararam o bloco "
                     "criptográfico). A última coluna é a cota empírica "
                     "do custo unitário da verificação AES-CMAC + FV. "
                     "A interpretação é confiável apenas quando "
                     "``frames p/ MAC'' é grande: em \\texttt{dos-py} e "
                     "\\texttt{dos-cangen} o atacante usa IDs fora da "
                     "allowlist e quase nenhum frame chega ao bloco "
                     "criptográfico, então a divisão por um denominador "
                     "pequeno amplifica o ruído amostral. O caso "
                     "diagnóstico é \\texttt{spoofing}, onde "
                     "$\\sim 30$\\,k frames por run com IDs legítimos "
                     "disparam a verificação."),
            label="tab:mac-overhead-evidence",
        )
        print(f"  ✓ mac_overhead_evidence.tex")

    # ---- Custo por autenticação SecOC (cen3/sender) ----
    cost_auth = build_cost_per_auth_table(perf, gw)
    if not cost_auth.empty:
        cpa_csv = master / "cost_per_auth.csv"
        cost_auth.to_csv(cpa_csv, index=False)
        print(f"\n  ✓ cost_per_auth.csv   ({len(cost_auth):,} linhas) → {cpa_csv}")

        # Tabela wide (1 coluna: cen3/sender) — usamos to_wide_absolute,
        # ele já lida bem com um único par (cenário, componente).
        write_latex(
            to_wide_absolute(cost_auth, "cycles", scale=1e3, decimals=1, latex=True),
            master / "cost_per_auth_cycles.tex",
            caption=("Custo computacional por autenticação SecOC: ciclos de "
                     "CPU por frame efetivamente autenticado pelo sender "
                     "($\\times 10^{3}$, média $\\pm$ IC$_{95}$, n=20). "
                     "Denominador: \\texttt{authenticated\\_tx} do "
                     "\\texttt{sender.log}. Isola o custo unitário do "
                     "AES-CMAC + atualização de FV + escrita do frame "
                     "protegido."),
            label="tab:cost-per-auth-cycles",
        )
        write_latex(
            to_wide_absolute(cost_auth, "instructions", scale=1e3, decimals=1, latex=True),
            master / "cost_per_auth_instructions.tex",
            caption=("Instruções executadas por autenticação SecOC "
                     "($\\times 10^{3}$, média $\\pm$ IC$_{95}$, n=20)."),
            label="tab:cost-per-auth-instructions",
        )
        print(f"  ✓ cost_per_auth_{{cycles,instructions}}.tex")

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
    if not cost_auth.empty:
        print_cost_per_auth(cost_auth)
    if not mac_ev.empty:
        print_block("EVIDÊNCIA DO CUSTO MAC SOB ATAQUE COM ID LEGÍTIMO")
        print("  Δ ciclos = cen3-gateway − cen2-gateway (somado nos n_runs).")
        print("  frames_p/MAC = rx_total − blocked_id (cen3): frames que")
        print("                 passaram o filtro de ID e dispararam o CMAC.")
        for _, r in mac_ev.iterrows():
            print(f"  • {r['attack']:>11}  "
                  f"frames_p/MAC = {r['reached_mac_mean']:>10,.0f}  "
                  f"Δciclos = {r['delta_cycles_mean']:>16,.0f}  "
                  f"ciclos/check = {r['cycles_per_mac_check_mean']:>12,.1f} "
                  f"± {r['cycles_per_mac_check_ci95_half']:>10,.1f}")

    print()
    print("Próximos passos:")
    print(f"  - Inspecione absolute_cost_wide.csv (legível em qualquer editor).")
    print(f"  - \\input{{absolute_cost_cycles.tex}} no capítulo de Resultados.")
    if not cost_auth.empty:
        print(f"  - \\input{{cost_per_auth_cycles.tex}} para reportar o custo "
              f"unitário do SecOC.")
    print(f"  - Para gráficos: rode plot_absolute.py (próxima etapa).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
