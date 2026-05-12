# Lê os logs `candump -t a -L` capturados pela campanha SYSTEM-WIDE+B
# (master_run_sw.sh) e computa, por (cenário, ataque, run, ID legítimo):
#
#   * latência de encaminhamento (forward latency) — tempo entre o frame
#     entrar no gateway e sair, em microssegundos. Pareamento FIFO por ID.
#   * inter-arrival jitter no receptor — desvio-padrão do espaçamento
#     entre frames consecutivos do mesmo ID na saída.
#
# Decomposição em cenário 3
# 
# O cen3 captura em 3 interfaces (vcan_trust, vcan0, vcan1):
#
#     vcan_trust  → vcan0 = latência do SENDER (assinar MAC + emitir)
#     vcan0       → vcan1 = latência do GATEWAY (verificar MAC + encaminhar)
#     vcan_trust  → vcan1 = latência TOTAL (sender + gateway, fim a fim)
#
# Para o cen2, só há gateway: latência = vcan0 → vcan1.
# Para o baseline, não há gateway, então só reportamos jitter em vcan0.
#
# Pareamento FIFO por ID
# 
# Para cada ID legítimo (244, 188, 19B), os frames são enfileirados na
# ordem temporal em cada interface. O k-ésimo frame da entrada corresponde
# ao k-ésimo frame da saída (gateway é single-threaded e mantém ordem).
# Se houver descasamento de contagem (e.g., gateway descartou um frame),
# truncamos para min(len_in, len_out) e logamos a diferença.

from __future__ import annotations

import argparse
import math
import re
import sys
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd


# Constantes
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.constants import LEGITIMATE_IDS, SCENARIO_STAGES

from lib.stats import t_value

# Parser candump — implementação compartilhada em lib.perf_io
from lib.perf_io import parse_candump as _parse_candump


def parse_candump(path: Path,
                  ids: Iterable[str] = LEGITIMATE_IDS) -> pd.DataFrame:
    """Wrapper local — preserva default de IDs alinhado com LEGITIMATE_IDS."""
    return _parse_candump(path, ids=ids)


# Pareamento FIFO por ID e cálculo de latências
def fifo_latencies(in_df: pd.DataFrame,
                   out_df: pd.DataFrame) -> pd.DataFrame:
    """
    Para cada ID em LEGITIMATE_IDS:
      * ordena entradas e saídas por timestamp
      * trunca para min(len_in, len_out)
      * pareia k-ésimo input com k-ésimo output → latency_us = (t_out - t_in) * 1e6
    Retorna DataFrame [id, latency_us].
    """
    out_rows = []
    for cid in sorted(LEGITIMATE_IDS):
        ins = in_df[in_df["id"] == cid].sort_values("ts")["ts"].values
        outs = out_df[out_df["id"] == cid].sort_values("ts")["ts"].values
        n = min(len(ins), len(outs))
        if n == 0:
            continue
        # Latência do k-ésimo frame.
        lat = (outs[:n] - ins[:n]) * 1e6
        # Filtra latências absurdamente negativas (clock skew leve em vcan
        # mostra ±5 µs no pior caso; aceitamos até -50 µs como ruído).
        lat = lat[lat >= -50.0]
        for v in lat:
            out_rows.append({"id": cid, "latency_us": float(v)})
    return pd.DataFrame(out_rows)


def inter_arrival_jitter(df: pd.DataFrame) -> pd.DataFrame:
    """
    Para cada ID, computa o desvio-padrão do espaçamento entre frames
    consecutivos (em µs). Retorna DataFrame [id, ia_mean_us, ia_std_us, n].
    """
    rows = []
    for cid in sorted(LEGITIMATE_IDS):
        ts = df[df["id"] == cid].sort_values("ts")["ts"].values
        if len(ts) < 3:
            continue
        deltas = np.diff(ts) * 1e6
        rows.append({
            "id": cid,
            "ia_mean_us": float(np.mean(deltas)),
            "ia_std_us":  float(np.std(deltas, ddof=1)),
            "n":          int(len(deltas)),
        })
    return pd.DataFrame(rows)


# Localizadores de logs (lidam com pequenas diferenças de layout entre cenários)
def find_run_dirs_baseline(master: Path) -> dict[tuple[str, int], Path]:
    """
    baseline grava em <master>/baseline (cópia de experiment_log) e os logs
    candump dentro de ataques/results-sw/lat_runs/<attack>_run<NN>/.
    """
    found: dict[tuple[str, int], Path] = {}
    candidates = [
        master / "baseline" / "lat_runs",
        master.parent.parent / "ataques" / "results-sw" / "lat_runs",
    ]
    for root in candidates:
        if not root.is_dir():
            continue
        for d in sorted(root.iterdir()):
            m = re.match(r"^(?P<atk>[a-z][a-z0-9-]+)_run(?P<run>\d+)$", d.name)
            if not m or not d.is_dir():
                continue
            atk = m.group("atk")
            run = int(m.group("run"))
            if (atk, run) not in found:
                found[(atk, run)] = d
    return found


def find_run_dirs_scenario(master: Path, scenario: str) -> dict[tuple[str, int], Path]:
    """cen2 e cen3 movem cada rodada para <master>/<cenarioN>/runs/."""
    cen_n = "cenario2" if scenario == "cen2" else "cenario3"
    root = master / cen_n / "runs"
    found: dict[tuple[str, int], Path] = {}
    if not root.is_dir():
        return found
    for d in sorted(root.iterdir()):
        m = re.match(r"^(?P<atk>[a-z][a-z0-9-]+)_run(?P<run>\d+)$", d.name)
        if not m or not d.is_dir():
            continue
        found[(m.group("atk"), int(m.group("run")))] = d
    return found


# Pipeline principal por cenário
def process_baseline(master: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Baseline só tem jitter de inter-chegada (não há gateway → sem latência)."""
    runs = find_run_dirs_baseline(master)
    lat_rows: list[dict] = []
    jit_rows: list[dict] = []
    for (atk, run), d in runs.items():
        f_in = d / "can_in.log"
        df_in = parse_candump(f_in)
        if df_in.empty:
            continue
        ia = inter_arrival_jitter(df_in)
        for _, r in ia.iterrows():
            jit_rows.append({
                "scenario": "baseline", "attack": atk, "run": run,
                "id": r["id"],
                "ia_mean_us": r["ia_mean_us"], "ia_std_us": r["ia_std_us"],
                "n": int(r["n"]),
            })
    return pd.DataFrame(lat_rows), pd.DataFrame(jit_rows)


def process_scenario(master: Path, scenario: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    runs = find_run_dirs_scenario(master, scenario)
    stages = SCENARIO_STAGES[scenario]
    lat_rows: list[dict] = []
    jit_rows: list[dict] = []
    for (atk, run), d in runs.items():
        # Latência por etapa
        for stage_label, fin_name, fout_name in stages:
            f_in = d / fin_name
            f_out = d / fout_name
            if not (f_in.is_file() and f_out.is_file()):
                continue
            df_in = parse_candump(f_in)
            df_out = parse_candump(f_out)
            lats = fifo_latencies(df_in, df_out)
            for _, r in lats.iterrows():
                lat_rows.append({
                    "scenario": scenario, "attack": atk, "run": run,
                    "stage": stage_label, "id": r["id"],
                    "latency_us": float(r["latency_us"]),
                })
        # Jitter no receptor (vcan_out)
        f_out = d / "can_out.log"
        if f_out.is_file():
            df_out = parse_candump(f_out)
            ia = inter_arrival_jitter(df_out)
            for _, r in ia.iterrows():
                jit_rows.append({
                    "scenario": scenario, "attack": atk, "run": run,
                    "id": r["id"],
                    "ia_mean_us": r["ia_mean_us"], "ia_std_us": r["ia_std_us"],
                    "n": int(r["n"]),
                })
    return pd.DataFrame(lat_rows), pd.DataFrame(jit_rows)


# Agregação estatística
def aggregate_latency(lat: pd.DataFrame) -> pd.DataFrame:
    """
    Por (scenario, attack, stage) agrega:
      n  : número de pares input-output
      mean, std, min, p50, p95, p99, max  (em µs)
      ic95_half  (de mean, t-Student)
    """
    if lat.empty:
        return pd.DataFrame()
    rows = []
    for (sc, atk, stage), grp in lat.groupby(["scenario", "attack", "stage"]):
        v = grp["latency_us"].values
        if len(v) < 1:
            continue
        n = len(v)
        mean = float(np.mean(v))
        std = float(np.std(v, ddof=1)) if n > 1 else 0.0
        ic = (t_value(n - 1) * std / math.sqrt(n)) if n > 1 else 0.0
        rows.append({
            "scenario": sc, "attack": atk, "stage": stage,
            "n": n,
            "mean_us": mean, "std_us": std, "ic95_half_us": ic,
            "min_us":  float(np.min(v)),
            "p50_us":  float(np.percentile(v, 50)),
            "p95_us":  float(np.percentile(v, 95)),
            "p99_us":  float(np.percentile(v, 99)),
            "max_us":  float(np.max(v)),
        })
    out = pd.DataFrame(rows)
    for c in ("mean_us", "std_us", "ic95_half_us",
              "min_us", "p50_us", "p95_us", "p99_us", "max_us"):
        out[c] = out[c].astype(float).round(2)
    return out


def aggregate_jitter(jit: pd.DataFrame) -> pd.DataFrame:
    """Por (scenario, attack) agrega ia_mean_us e ia_std_us média + IC95."""
    if jit.empty:
        return pd.DataFrame()
    rows = []
    for (sc, atk), grp in jit.groupby(["scenario", "attack"]):
        # Pondera pelas observações por rodada — mas aqui simplificamos:
        # usamos a média das estatísticas por rodada (cada rodada é
        # independente, n≥10 rodadas dão IC95 razoável).
        per_run_jitter = grp.groupby("run")["ia_std_us"].mean().values
        if len(per_run_jitter) < 1:
            continue
        n = len(per_run_jitter)
        mean = float(np.mean(per_run_jitter))
        std = float(np.std(per_run_jitter, ddof=1)) if n > 1 else 0.0
        ic = (t_value(n - 1) * std / math.sqrt(n)) if n > 1 else 0.0
        rows.append({
            "scenario": sc, "attack": atk,
            "n_runs": n,
            "jitter_mean_us": mean,
            "jitter_std_us":  std,
            "jitter_ic95_us": ic,
        })
    out = pd.DataFrame(rows)
    for c in ("jitter_mean_us", "jitter_std_us", "jitter_ic95_us"):
        out[c] = out[c].astype(float).round(2)
    return out


# LaTeX
from lib.latex import write_table, format_cell


def write_latex_summary(summary: pd.DataFrame, out_path: Path) -> None:
    """Tabela linhas=(stage,attack); colunas=μ,p50,p95,p99 em µs."""
    if summary.empty:
        out_path.write_text("% (tabela vazia)\n", encoding="utf-8")
        return

    cols = ["scenario", "stage", "attack",
            "mean_us", "p50_us", "p95_us", "p99_us"]
    missing = [c for c in cols if c not in summary.columns]
    if missing:
        out_path.write_text(f"% colunas ausentes: {missing}\n",
                            encoding="utf-8")
        return

    df = summary[cols].copy()
    df.rename(columns={
        "scenario": "cenário", "stage": "etapa", "attack": "ataque",
        "mean_us": r"$\mu$ (µs)", "p50_us": "p50 (µs)",
        "p95_us": "p95 (µs)", "p99_us": "p99 (µs)",
    }, inplace=True)

    align = "lll" + "r" * (len(df.columns) - 3)
    write_table(
        df, out_path,
        caption=("Latência de encaminhamento por cenário/etapa/ataque "
                 "(µs, sumário sobre todas as rodadas)."),
        label="tab:latency-summary",
        align=align,
        generator_comment="% Gerado por analyze_latency.py — não editar à mão.",
        cell_formatter=lambda v: format_cell(v, float_decimals=2),
    )


# Main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Calcula latência de encaminhamento e jitter a partir "
                    "dos logs candump da campanha SW+B."
    )
    ap.add_argument("--master-dir", type=Path, required=True,
                    help="Diretório resultados-sw/<timestamp>/")
    args = ap.parse_args()

    master = args.master_dir.resolve()
    if not master.is_dir():
        print(f"[ERRO] {master} não é um diretório.", file=sys.stderr)
        return 1

    print()
    print("=" * 68)
    print("  ANÁLISE DE LATÊNCIA + JITTER (Etapa B)")
    print(f"  master_dir : {master}")
    print("=" * 68)

    # Coleta por cenário
    lat_b, jit_b = process_baseline(master)
    lat_2, jit_2 = process_scenario(master, "cen2")
    lat_3, jit_3 = process_scenario(master, "cen3")

    lat_all = pd.concat([lat_b, lat_2, lat_3], ignore_index=True)
    jit_all = pd.concat([jit_b, jit_2, jit_3], ignore_index=True)

    # Salva CSV cru
    lat_all_path = master / "latency_per_run.csv"
    lat_all.to_csv(lat_all_path, index=False)
    print(f"  ✓ {lat_all_path.name} ({len(lat_all):,} pares de frames)")

    # Agrega latência
    summary = aggregate_latency(lat_all)
    sum_path = master / "latency_summary.csv"
    summary.to_csv(sum_path, index=False)
    print(f"  ✓ {sum_path.name} ({len(summary):,} agrupamentos)")

    # Agrega jitter
    jit_summary = aggregate_jitter(jit_all)
    jit_path = master / "jitter_summary.csv"
    jit_summary.to_csv(jit_path, index=False)
    print(f"  ✓ {jit_path.name} ({len(jit_summary):,} pares (cen, atk))")

    # LaTeX
    tex_path = master / "latency_summary.tex"
    write_latex_summary(summary, tex_path)
    print(f"  ✓ {tex_path.name}")

    # Resumo no console
    print()
    if not summary.empty:
        print("=== Latência média por (cenário, etapa, ataque) — µs ===")
        for sc in ("cen2", "cen3"):
            sub = summary[summary.scenario == sc]
            if sub.empty:
                continue
            print(f"\n[{sc}]")
            for _, r in sub.sort_values(["stage", "attack"]).iterrows():
                print(f"   {r['stage']:>14} / {r['attack']:>10}: "
                      f"μ={r['mean_us']:>8.2f}  p50={r['p50_us']:>7.2f}  "
                      f"p95={r['p95_us']:>8.2f}  p99={r['p99_us']:>9.2f}  "
                      f"(n={int(r['n']):>6,})")
    if not jit_summary.empty:
        print()
        print("=== Jitter de inter-chegada (vcan de saída) — µs ===")
        for _, r in jit_summary.sort_values(["scenario", "attack"]).iterrows():
            print(f"   [{r['scenario']:>8}] {r['attack']:>10}: "
                  f"σ_inter = {r['jitter_mean_us']:>9.2f} ± "
                  f"{r['jitter_ic95_us']:>6.2f} µs (n_runs={int(r['n_runs'])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
