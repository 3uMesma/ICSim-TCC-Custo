# Helpers para geração de tabelas LaTeX no padrão booktabs do TCC.

from __future__ import annotations

import math
from pathlib import Path

import pandas as pd


def escape(s: str) -> str:
    """Escapa caracteres especiais de LaTeX em string crua."""
    return (s.replace("\\", r"\textbackslash{}")
             .replace("&", r"\&")
             .replace("%", r"\%")
             .replace("_", r"\_")
             .replace("#", r"\#")
             .replace("$", r"\$")
             .replace("{", r"\{")
             .replace("}", r"\}"))


def looks_like_latex(s: str) -> bool:
    """Heurística: célula contém comandos LaTeX (não escapar)."""
    return ("$" in s) or ("\\" in s)


def format_cell(value, *, float_decimals: int = 4) -> str:
    """Formata uma célula para LaTeX. Trata float (vírgula de milhar,
    NaN→'—') e string (escapa se não parecer LaTeX)."""
    if isinstance(value, str):
        return value if looks_like_latex(value) else escape(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "—"
        return f"{value:,.{float_decimals}f}"
    return str(value)


def format_cell_scientific(value, *, float_decimals: int = 2) -> str:
    """Variante usada por analyze_all.py — escolhe entre notação científica
    e fixa baseado na magnitude. NaN renderiza como '--' (não '—')."""
    if isinstance(value, str):
        if looks_like_latex(value):
            return value
        return escape(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "--"
        if abs(value) >= 1e6 or (0 < abs(value) < 1e-2):
            return f"{value:.3e}"
        return f"{value:,.{float_decimals}f}"
    return escape(str(value))


def write_table(
    df: pd.DataFrame,
    out_path: Path,
    *,
    caption: str,
    label: str,
    align: str | None = None,
    generator_comment: str = "% Gerado automaticamente — não editar à mão.",
    cell_formatter=None,
) -> None:
    """Escreve tabela no padrão booktabs (toprule/midrule/bottomrule).

    - `align`: string LaTeX (ex.: "lrr"). Se None: 1 'l' + (cols-1) 'r'.
    - `cell_formatter`: callable(value) → str. Default = format_cell.
    """
    if df.empty:
        out_path.write_text("% (tabela vazia)\n", encoding="utf-8")
        return

    cols = list(df.columns)
    if align is None:
        align = "l" + "r" * (len(cols) - 1)

    fmt = cell_formatter or format_cell

    lines = [
        generator_comment,
        r"\begin{table}[!ht]",
        r"\centering",
        r"\small",
        rf"\caption{{{caption}}}",
        rf"\label{{{label}}}",
        rf"\begin{{tabular}}{{{align}}}",
        r"\toprule",
        " & ".join(fmt(c) for c in cols) + r" \\",
        r"\midrule",
    ]
    for _, row in df.iterrows():
        lines.append(" & ".join(fmt(row[c]) for c in cols) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}", ""]
    out_path.write_text("\n".join(lines), encoding="utf-8")
