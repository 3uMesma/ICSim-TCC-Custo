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


# Pareamento payload-aware com janela temporal adaptativa
#
# Substitui o pareamento FIFO antigo (k-ésimo in com k-ésimo out), que
# falha quando o gateway dropa frames do mesmo ID — exatamente o caso de
# replay/spoofing onde o atacante repete IDs legítimos e parte dos frames
# é bloqueada por rate-limit, DLC ou FV/MAC.
#
# Estratégia
# ----------
# 1. Para cada ID legítimo, canonicaliza o payload tomando os primeiros
#    `min(dlc_in, dlc_out)` bytes — assim cen3 (gateway com strip=1, que
#    remove FV+MAC ao escrever em vcan1) e cen2 (sem strip) usam o mesmo
#    discriminador.
# 2. Para cada frame em `out`, busca o frame em `in` com mesmo (id,
#    payload_canon) cujo t_in seja o mais recente menor ou igual a t_out
#    e dentro de uma janela temporal máxima.
# 3. Janela temporal ADAPTATIVA:
#    - Passada 1 com janela ampla (max_window_us) para estimar latência típica.
#    - p95 das latências encontradas × FOLD define a janela final.
#    - Cap inferior em min_window_us (evita degeneração para zero).
#    - Cap superior em max_window_us (evita runaway no replay).
#    - Passada 2 com a janela adaptativa, descartando outliers.
# 4. Reporta cobertura: quantos frames de saída conseguiram parear.

# Constantes da heurística adaptativa. Cap superior de 2 s é
# deliberadamente generoso — vcan em vazio tem latências de poucos µs,
# então qualquer coisa acima de 2 s é certamente pareamento errado.
ADAPTIVE_MIN_WINDOW_US = 50_000      # 50 ms
ADAPTIVE_MAX_WINDOW_US = 2_000_000   # 2 s
ADAPTIVE_FOLD          = 3.0         # janela final = max(min, fold × p95)
NEG_TOLERANCE_US       = 50.0        # aceita até -50µs (clock skew em vcan)


def _canon_payload(data_hex: str, max_len_bytes: int) -> str:
    """Trunca payload hex (data_hex já vem em maiúscula, sem espaços) para
    `max_len_bytes` bytes (= 2 chars hex cada). Comparações de payload em
    cen3 precisam disso porque o gateway com strip=1 escreve em vcan1 só
    os primeiros 5 bytes (sem FV/MAC)."""
    if max_len_bytes <= 0:
        return ""
    return data_hex[: max_len_bytes * 2]


def _pair_with_window(in_df: pd.DataFrame,
                      out_df: pd.DataFrame,
                      window_us: float) -> tuple[list[dict], int, int]:
    """Pareamento (id, payload_canonico) com busca do `t_in` mais recente
    em janela. Retorna (lista de pares, n_in_total, n_out_total) sobre os
    IDs legítimos.

    Implementação: para cada (id, payload_canon) constrói lista ordenada
    de timestamps de entrada e usa np.searchsorted para localizar o
    candidato mais recente menor que t_out.
    """
    # n_in/n_out informativos para cobertura — só conta IDs legítimos.
    in_leg = in_df[in_df["id"].isin(LEGITIMATE_IDS)]
    out_leg = out_df[out_df["id"].isin(LEGITIMATE_IDS)]
    n_in = len(in_leg)
    n_out = len(out_leg)

    if n_in == 0 or n_out == 0:
        return [], n_in, n_out

    pairs: list[dict] = []

    # Itera por ID; dentro de cada ID, agrupa por payload_canon.
    for cid in sorted(LEGITIMATE_IDS):
        sub_in = in_leg[in_leg["id"] == cid].sort_values("ts")
        sub_out = out_leg[out_leg["id"] == cid].sort_values("ts")
        if sub_in.empty or sub_out.empty:
            continue

        # Determina o comprimento canônico para este ID neste run.
        # Usamos o MÍNIMO comprimento observado na SAÍDA — porque a saída
        # contém apenas frames que passaram pelo gateway, então o DLC é
        # bem-definido (não há fuzz com DLC quebrado). Em cen3 com
        # strip=1, min_out_len corresponde ao payload "plain" (5B). Em
        # cen2/cen3 sem strip, equivale ao DLC nativo. Frames em `in`
        # com DLC menor que o canônico não podem casar e ficam de fora —
        # mas eles tampouco passariam pelo gateway, então isso é OK.
        if sub_out.empty:
            continue
        min_out_len = int(sub_out["data"].str.len().min())
        canon_chars = min_out_len
        canon_bytes = canon_chars // 2
        if canon_bytes == 0:
            continue

        # Indexa entradas por payload_canon: dict payload -> sorted ts array.
        # Frames em `in` com data mais curto que canon_chars são ignorados.
        in_by_payload: dict[str, np.ndarray] = {}
        for ts, data in zip(sub_in["ts"].values, sub_in["data"].values):
            if len(data) < canon_chars:
                continue
            key = _canon_payload(data, canon_bytes)
            in_by_payload.setdefault(key, []).append(ts)
        for k in in_by_payload:
            in_by_payload[k] = np.asarray(sorted(in_by_payload[k]))

        # Para cada saída, busca o t_in mais recente que satisfaça janela.
        # Marca cada t_in usado (set) para evitar reuso (1:1).
        used: set[tuple[str, float]] = set()
        for ts_out, data_out in zip(sub_out["ts"].values, sub_out["data"].values):
            key = _canon_payload(data_out, canon_bytes)
            ts_arr = in_by_payload.get(key)
            if ts_arr is None or len(ts_arr) == 0:
                continue
            # idx: maior posição com ts_arr[idx] <= ts_out.
            idx = int(np.searchsorted(ts_arr, ts_out, side="right") - 1)
            # Procura para trás se já usado, mantendo a janela e a regra
            # de t_in <= t_out. (Caso comum: idx é único; caso replay com
            # repetição de payload, descer no array busca um match
            # anterior livre.)
            while idx >= 0:
                t_in = float(ts_arr[idx])
                lat_us = (ts_out - t_in) * 1e6
                if lat_us > window_us:
                    break  # entradas mais antigas estão ainda mais longe
                if lat_us < -NEG_TOLERANCE_US:
                    idx -= 1
                    continue
                if (key, t_in) in used:
                    idx -= 1
                    continue
                used.add((key, t_in))
                pairs.append({"id": cid, "latency_us": float(lat_us)})
                break
            # se loop terminar sem break, nenhum candidato — frame não pareia
    return pairs, n_in, n_out


def payload_window_latencies(
    in_df: pd.DataFrame,
    out_df: pd.DataFrame,
    min_window_us: float = ADAPTIVE_MIN_WINDOW_US,
    max_window_us: float = ADAPTIVE_MAX_WINDOW_US,
    fold: float = ADAPTIVE_FOLD,
) -> tuple[pd.DataFrame, dict]:
    """Pareamento adaptativo. Retorna (DataFrame [id, latency_us], info).

    `info` contém:
      window_us       : janela final adotada (passada 2)
      window_round1_us: janela inicial (= max_window_us)
      n_in            : número de frames legítimos vistos na entrada
      n_out           : número de frames legítimos vistos na saída
      n_paired        : número de pares válidos retornados
    """
    # Passada 1: janela ampla.
    pairs_r1, n_in, n_out = _pair_with_window(in_df, out_df, max_window_us)
    info = {
        "window_round1_us": float(max_window_us),
        "n_in": int(n_in),
        "n_out": int(n_out),
        "n_paired": 0,
        "window_us": float(max_window_us),
    }
    if len(pairs_r1) < 10:
        # Amostra pequena demais para adaptar — retorna passada 1 e
        # registra janela = max_window_us (sem refinamento).
        info["n_paired"] = len(pairs_r1)
        return pd.DataFrame(pairs_r1), info

    lat_r1 = np.array([p["latency_us"] for p in pairs_r1])
    p95 = float(np.percentile(lat_r1, 95))
    adaptive = max(min_window_us, min(max_window_us, p95 * fold))
    if adaptive >= max_window_us * 0.99:
        # Janela adaptativa coincide com a inicial — reaproveita.
        info["window_us"] = float(max_window_us)
        info["n_paired"] = len(pairs_r1)
        return pd.DataFrame(pairs_r1), info

    # Passada 2: janela adaptativa.
    pairs_r2, _, _ = _pair_with_window(in_df, out_df, adaptive)
    info["window_us"] = float(adaptive)
    info["n_paired"] = len(pairs_r2)
    return pd.DataFrame(pairs_r2), info


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
def find_run_dirs_for(master: Path, scenario: str) -> dict[tuple[str, int], Path]:
    """Mapeia (attack, run) -> diretório candump para os três cenários.

    Layout pós-migração:
      baseline -> <master>/baseline/runs/<attack>_run<NN>/
      cen2     -> <master>/cenario2/runs/<attack>_run<NN>/
      cen3     -> <master>/cenario3/runs/<attack>_run<NN>/

    Layouts antigos (campanhas pré-migração) ainda são suportados como
    fallback para que reanálises de dados históricos não quebrem.
    """
    candidates: list[Path] = []
    if scenario == "baseline":
        candidates.extend([
            master / "baseline" / "runs",
            master / "baseline" / "lat_runs",   # layout antigo (pré-passthrough)
            master.parent.parent / "ataques" / "results-sw" / "lat_runs",
        ])
    elif scenario == "cen2":
        candidates.append(master / "cenario2" / "runs")
    elif scenario == "cen3":
        candidates.extend([master / "cenario3" / "runs", master / "cenario3"])

    found: dict[tuple[str, int], Path] = {}
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


# Pipeline principal por cenário
#
# Cada cenário (baseline, cen2, cen3) usa os mesmos três produtos:
#   - lat_rows: pares (cenário, ataque, run, stage, id, latency_us)
#   - jit_rows: estatística inter-chegada no receptor
#   - cov_rows: cobertura do pareamento por (cenário, ataque, run, stage)
def _process_one_scenario(master: Path, scenario: str
                          ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    runs = find_run_dirs_for(master, scenario)
    stages = SCENARIO_STAGES.get(scenario, [])
    lat_rows: list[dict] = []
    jit_rows: list[dict] = []
    cov_rows: list[dict] = []

    for (atk, run), d in runs.items():
        for stage_label, fin_name, fout_name in stages:
            f_in = d / fin_name
            f_out = d / fout_name
            if not (f_in.is_file() and f_out.is_file()):
                continue
            df_in = parse_candump(f_in)
            df_out = parse_candump(f_out)
            lats_df, info = payload_window_latencies(df_in, df_out)
            for _, r in lats_df.iterrows():
                lat_rows.append({
                    "scenario": scenario, "attack": atk, "run": run,
                    "stage": stage_label, "id": r["id"],
                    "latency_us": float(r["latency_us"]),
                })
            cov_rows.append({
                "scenario": scenario, "attack": atk, "run": run,
                "stage": stage_label,
                "n_in": info["n_in"], "n_out": info["n_out"],
                "n_paired": info["n_paired"],
                "window_us": info["window_us"],
            })

        # Jitter no receptor. Preferimos can_out.log (saída do gateway),
        # mas para baseline isolado podemos usar can_in.log se can_out
        # estiver vazio (preserva o comportamento histórico).
        f_jit = d / "can_out.log"
        if not f_jit.is_file() or f_jit.stat().st_size == 0:
            f_jit = d / "can_in.log"
        if f_jit.is_file():
            df_jit = parse_candump(f_jit)
            ia = inter_arrival_jitter(df_jit)
            for _, r in ia.iterrows():
                jit_rows.append({
                    "scenario": scenario, "attack": atk, "run": run,
                    "id": r["id"],
                    "ia_mean_us": r["ia_mean_us"], "ia_std_us": r["ia_std_us"],
                    "n": int(r["n"]),
                })
    return (pd.DataFrame(lat_rows),
            pd.DataFrame(jit_rows),
            pd.DataFrame(cov_rows))


def process_baseline(master: Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Baseline (passthrough): cadeia vcan0->vcan1 igual a cen2."""
    return _process_one_scenario(master, "baseline")


def process_scenario(master: Path, scenario: str
                     ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    return _process_one_scenario(master, scenario)


# Agregação estatística
# Limiares de qualidade da cobertura (usados no LaTeX/console):
# coverage = n_paired / max(n_in, n_out). 30% é limite mínimo para 
# reportar com aviso (abaixo disso, a entrada não aparece no relatório).
COVERAGE_GOOD_PCT = 80.0
COVERAGE_MIN_PCT  = 30.0


def aggregate_latency(lat: pd.DataFrame,
                      cov: pd.DataFrame | None = None) -> pd.DataFrame:
    """Por (scenario, attack, stage) agrega:
      n  : número de pares input-output retornados pelo pareamento
      mean, std, min, p50, p95, p99, max  (em µs)
      ic95_half  (de mean, t-Student)
      n_in_total, n_out_total: frames legítimos vistos nos dois lados
      coverage_pct: 100 · n_paired / max(n_in_total, n_out_total)
      window_mean_us: janela adaptativa média (informativo para o leitor)
      quality: "ok" | "warn" | "bad" — para destacar no relatório
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
        row = {
            "scenario": sc, "attack": atk, "stage": stage,
            "n": n,
            "mean_us": mean, "std_us": std, "ic95_half_us": ic,
            "min_us":  float(np.min(v)),
            "p50_us":  float(np.percentile(v, 50)),
            "p95_us":  float(np.percentile(v, 95)),
            "p99_us":  float(np.percentile(v, 99)),
            "max_us":  float(np.max(v)),
        }
        if cov is not None and not cov.empty:
            cov_sub = cov[(cov.scenario == sc) & (cov.attack == atk)
                          & (cov.stage == stage)]
            if not cov_sub.empty:
                n_in_total  = int(cov_sub["n_in"].sum())
                n_out_total = int(cov_sub["n_out"].sum())
                n_paired    = int(cov_sub["n_paired"].sum())
                denom = max(n_in_total, n_out_total, 1)
                coverage_pct = 100.0 * n_paired / denom
                row["n_in_total"]  = n_in_total
                row["n_out_total"] = n_out_total
                row["coverage_pct"] = round(coverage_pct, 2)
                row["window_mean_us"] = float(np.mean(cov_sub["window_us"]))
                if coverage_pct >= COVERAGE_GOOD_PCT:
                    row["quality"] = "ok"
                elif coverage_pct >= COVERAGE_MIN_PCT:
                    row["quality"] = "warn"
                else:
                    row["quality"] = "bad"
        rows.append(row)
    out = pd.DataFrame(rows)
    for c in ("mean_us", "std_us", "ic95_half_us",
              "min_us", "p50_us", "p95_us", "p99_us", "max_us"):
        if c in out.columns:
            out[c] = out[c].astype(float).round(2)
    if "window_mean_us" in out.columns:
        out["window_mean_us"] = out["window_mean_us"].astype(float).round(1)
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
    """Tabela linhas=(scenario,stage,attack); colunas=μ,p50,p95,p99,cobertura.

    Inclui todas as linhas. Cobertura aparece como número adicional (útil
    para discussão na monografia), mas sem marcação visual diferenciada
    para casos de baixa cobertura — a discussão metodológica fica para o
    texto. As colunas auxiliares `quality` e `coverage_pct` permanecem
    disponíveis em `latency_summary.csv` para auditoria.
    """
    if summary.empty:
        out_path.write_text("% (tabela vazia)\n", encoding="utf-8")
        return

    base_cols = ["scenario", "stage", "attack",
                 "mean_us", "p50_us", "p95_us", "p99_us"]
    missing = [c for c in base_cols if c not in summary.columns]
    if missing:
        out_path.write_text(f"% colunas ausentes: {missing}\n",
                            encoding="utf-8")
        return

    df = summary.copy()
    cov_caption = ""
    if "coverage_pct" in df.columns:
        df["cobertura"] = df["coverage_pct"].map(lambda v: f"{v:.1f}\\%")
        base_cols = base_cols + ["cobertura"]
        cov_caption = (
            r" A coluna `cobertura' indica a fração de frames pareados "
            r"pelo algoritmo de matching payload-aware "
            r"(100\,$\cdot\,n_{paired}/\max(n_{in},n_{out})$).")

    df = df[base_cols].copy()
    df.rename(columns={
        "scenario": "cenário", "stage": "etapa", "attack": "ataque",
        "mean_us": r"$\mu$ (µs)", "p50_us": "p50 (µs)",
        "p95_us": "p95 (µs)", "p99_us": "p99 (µs)",
    }, inplace=True)

    align = "lll" + "r" * (len(df.columns) - 3)
    write_table(
        df, out_path,
        caption=("Latência de encaminhamento por cenário/etapa/ataque "
                 "(µs, sumário sobre todas as rodadas; pareamento "
                 "payload-aware com janela temporal adaptativa)." +
                 cov_caption),
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
    lat_b, jit_b, cov_b = process_baseline(master)
    lat_2, jit_2, cov_2 = process_scenario(master, "cen2")
    lat_3, jit_3, cov_3 = process_scenario(master, "cen3")

    lat_all = pd.concat([lat_b, lat_2, lat_3], ignore_index=True)
    jit_all = pd.concat([jit_b, jit_2, jit_3], ignore_index=True)
    cov_all = pd.concat([cov_b, cov_2, cov_3], ignore_index=True)

    # Salva CSV cru
    lat_all_path = master / "latency_per_run.csv"
    lat_all.to_csv(lat_all_path, index=False)
    print(f"  ✓ {lat_all_path.name} ({len(lat_all):,} pares de frames)")

    cov_path = master / "latency_coverage_per_run.csv"
    cov_all.to_csv(cov_path, index=False)
    print(f"  ✓ {cov_path.name} ({len(cov_all):,} linhas)")

    # Agrega latência (com cobertura)
    summary = aggregate_latency(lat_all, cov_all)
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
        for sc in ("baseline", "cen2", "cen3"):
            sub = summary[summary.scenario == sc]
            if sub.empty:
                continue
            print(f"\n[{sc}]")
            for _, r in sub.sort_values(["stage", "attack"]).iterrows():
                cov_tag = ""
                if "coverage_pct" in r and pd.notna(r.get("coverage_pct")):
                    cov_tag = f"  cov={r['coverage_pct']:>5.1f}%"
                win_tag = ""
                if "window_mean_us" in r and pd.notna(r.get("window_mean_us")):
                    win_tag = f"  win={r['window_mean_us']/1000:>6.1f}ms"
                print(f"   {r['stage']:>14} / {r['attack']:>10}: "
                      f"μ={r['mean_us']:>9.2f}  p50={r['p50_us']:>9.2f}  "
                      f"p95={r['p95_us']:>10.2f}  p99={r['p99_us']:>11.2f}  "
                      f"(n={int(r['n']):>6,}){cov_tag}{win_tag}")
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
