# Estatística descritiva: t de Student bicaudal e agregação com IC95.
# Implementação sem dependência de scipy — tabela tabulada (df=1..29)
# com interpolação linear; df>=30 usa aproximação z=1.96.

from __future__ import annotations

import math
from typing import Mapping

import numpy as np
import pandas as pd


T_TABLE_95: Mapping[int, float] = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447,  7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045,
}


def t_value(df: int) -> float:
    """t crítico bicaudal (α=0.05), interpolação linear na tabela.
    df<1 → inf (degenerate); df>=30 → 1.96."""
    if df < 1:
        return float("inf")
    if df in T_TABLE_95:
        return T_TABLE_95[df]
    keys = sorted(T_TABLE_95.keys())
    if df > keys[-1]:
        return 1.96
    for lo, hi in zip(keys[:-1], keys[1:]):
        if lo <= df <= hi:
            frac = (df - lo) / (hi - lo)
            return T_TABLE_95[lo] + frac * (T_TABLE_95[hi] - T_TABLE_95[lo])
    return 1.96


def aggregate_with_ci(values: pd.Series) -> dict:
    """μ, σ, CV%, IC95 a partir de uma série de valores.

    Replica exatamente `aggregate_stats` de analyze_absolute.py e equivalentes
    em analyze_latency.py / analyze_overhead_sw.py.

    Retorna dict com chaves: n, mean, std, cv_pct, ci95_half, ci95_low, ci95_high.
    """
    n = len(values)
    mean = float(values.mean()) if n else float("nan")
    std = float(values.std(ddof=1)) if n > 1 else 0.0
    cv = (std / mean * 100.0) if mean != 0 else 0.0
    if n > 1:
        half = t_value(n - 1) * std / math.sqrt(n)
    else:
        half = 0.0
    return {
        "n": n, "mean": mean, "std": std, "cv_pct": cv,
        "ci95_half": half,
        "ci95_low": mean - half, "ci95_high": mean + half,
    }


def aggregate_groupby(
    df: pd.DataFrame,
    group_cols: list[str],
    *,
    value_col: str = "value",
    keep_unit: bool = True,
) -> pd.DataFrame:
    """Versão vetorizada de aggregate_with_ci para uso com groupby.

    Replica exatamente `aggregate` de analyze_all.py e analyze_overhead_sw.py.
    Se `keep_unit=True` e a coluna 'unit' existir, ela entra como group_col.
    O caller é responsável por aplicar `.round(...)` e selecionar colunas.
    """
    cols = list(group_cols)
    if keep_unit and "unit" in df.columns and "unit" not in cols:
        cols = cols + ["unit"]
    g = df.groupby(cols)[value_col]
    stats = g.agg(["count", "mean", "std"]).reset_index()
    stats.columns = cols + ["n", "mean", "std"]
    stats["std"] = stats["std"].fillna(0.0)
    stats["cv_pct"] = np.where(
        stats["mean"] != 0, stats["std"] / stats["mean"] * 100.0, 0.0
    )
    stats["t_crit"] = stats["n"].apply(
        lambda n: t_value(int(n) - 1) if n > 1 else 0.0
    )
    stats["ci95_half"] = np.where(
        stats["n"] > 1,
        stats["t_crit"] * stats["std"] / np.sqrt(stats["n"]),
        0.0,
    )
    stats["ci95_low"] = stats["mean"] - stats["ci95_half"]
    stats["ci95_high"] = stats["mean"] + stats["ci95_half"]
    return stats
