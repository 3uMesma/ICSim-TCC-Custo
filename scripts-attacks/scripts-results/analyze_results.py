#!/usr/bin/env python3
"""
Lê os CSVs brutos de run_experiments.sh e produz summary.csv com:
  média, desvio padrão, coeficiente de variação e IC 95% (t de Student)
  agrupados por (ataque, métrica).
"""

import argparse
import os
import sys
import glob
from pathlib import Path
import pandas as pd
import numpy as np

# t de Student IC 95%, duas caudas (pra não precisar de scipy)
T_TABLE_95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    19: 2.093,
    24: 2.064,
    29: 2.045,
}


def t_value(df: int) -> float:
    if df in T_TABLE_95:
        return T_TABLE_95[df]
    keys = sorted(T_TABLE_95.keys())
    if df < keys[0]:
        return T_TABLE_95[keys[0]]
    if df > keys[-1]:
        return 1.96
    for i in range(len(keys) - 1):
        if keys[i] <= df <= keys[i + 1]:
            lo, hi = keys[i], keys[i + 1]
            frac = (df - lo) / (hi - lo)
            return T_TABLE_95[lo] + frac * (T_TABLE_95[hi] - T_TABLE_95[lo])
    return 1.96


def parse_csv_files(input_dir: str) -> pd.DataFrame:
    """Lê CSVs brutos. Formato: attack;run;metric;value;unit"""
    rows = []
    for fpath in sorted(glob.glob(os.path.join(input_dir, "*.csv"))):
        try:
            df = pd.read_csv(fpath, sep=";", dtype=str)
        except Exception as e:
            print(f"[AVISO] Erro lendo {fpath}: {e}")
            continue
        if df.empty or "metric" not in df.columns:
            continue
        df["value"] = df["value"].str.replace(",", ".", regex=False)
        df["value"] = pd.to_numeric(df["value"], errors="coerce")
        df.dropna(subset=["value"], inplace=True)
        rows.append(df)

    return pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()


def compute_statistics(df: pd.DataFrame) -> pd.DataFrame:
    grouped = df.groupby(["attack", "metric"])["value"]
    stats = grouped.agg(["count", "mean", "std"]).reset_index()
    stats.columns = ["attack", "metric", "n", "mean", "std"]
    stats["std"] = stats["std"].fillna(0)

    stats["cv_pct"] = np.where(
        stats["mean"] != 0, (stats["std"] / stats["mean"] * 100).round(2), 0
    )

    stats["ci95"] = stats.apply(
        lambda r: (
            t_value(max(1, int(r["n"]) - 1)) * r["std"] / np.sqrt(r["n"])
            if r["n"] > 1
            else 0
        ),
        axis=1,
    )

    stats["mean"] = stats["mean"].round(2)
    stats["std"] = stats["std"].round(2)
    stats["ci95"] = stats["ci95"].round(2)
    return stats


def main():
    parser = argparse.ArgumentParser(description="Análise estatística")
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", default="results/summary.csv")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  ANÁLISE ESTATÍSTICA")
    print(f"{'='*60}\n")

    df = parse_csv_files(args.input_dir)
    if df.empty:
        print("[ERRO] Nenhum dado para analisar.")
        return

    stats = compute_statistics(df)
    stats.to_csv(args.output, index=False, sep=";")
    print(f"  Salvo: {args.output}\n")

    for _, r in stats.iterrows():
        print(
            f"  {r['attack']:>12} | {r['metric']:>20} | "
            f"μ={r['mean']:>12,.1f} ± {r['ci95']:>8,.1f}  "
            f"(σ={r['std']:>10,.1f}, CV={r['cv_pct']:.1f}%, n={int(r['n'])})"
        )


if __name__ == "__main__":
    main()
