# Leitores e parsers para os formatos de I/O do experimento:
#   * perf_data.csv (formato canônico de lib/perf_csv.sh)
#   * gateway_logs.csv (saída de parse_gateway_logs.py)
#   * baseline CSV (attack;run;metric;value;unit)
#   * perf nativo (-x ',')
#   * candump -t a -L

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path
from typing import Iterable

import pandas as pd


CANONICAL_HEADER = [
    "scenario", "component", "attack", "run", "metric", "value", "unit",
]
RAW_HEADER = ["attack", "run", "metric", "value", "unit"]

CANDUMP_RE = re.compile(
    r"^\(\s*(?P<ts>[0-9]+\.[0-9]+)\)\s+\S+\s+"
    r"(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)\s*$"
)


def to_float(s: str) -> float | None:
    """Converte string numérica do perf, tolerante a locale BR e brancos.
    Retorna None para '<not counted>', '<not supported>', vazio, ou nan."""
    if s is None:
        return None
    s = s.strip()
    if not s or s.startswith("<") or s.lower() == "nan":
        return None
    s = s.replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None


def norm_metric(name: str) -> str:
    """Normaliza nomes de eventos do perf removendo modificadores (:u, :k)."""
    return re.sub(r":[uk]+$", "", name.strip())


def load_perf_csv(
    path: Path,
    *,
    component_filter: str | None = None,
) -> pd.DataFrame:
    """Lê perf_data.csv no formato canônico de lib/perf_csv.sh.
    Faz: sep=';', troca ',' por '.' em value, dropna, strip de strings,
    run→int. Opcionalmente filtra component (ex: 'system')."""
    df = pd.read_csv(path, sep=";", dtype=str)
    df["value"] = pd.to_numeric(
        df["value"].astype(str).str.replace(",", "."), errors="coerce"
    )
    df.dropna(subset=["value"], inplace=True)
    df["run"] = pd.to_numeric(df["run"], errors="coerce").fillna(0).astype(int)
    for col in ("scenario", "component", "attack", "metric", "unit"):
        df[col] = df[col].fillna("").astype(str).str.strip()
    if component_filter is not None:
        df = df[df["component"] == component_filter].copy()
    return df


def load_gateway_logs(path: Path) -> pd.DataFrame:
    """Lê gateway_logs.csv produzido por parse_gateway_logs.py."""
    df = pd.read_csv(path, sep=";", dtype={"run": int})
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df.dropna(subset=["value"], inplace=True)
    return df


def parse_baseline_csv(
    path: Path,
    default_attack: str | None = None,
) -> list[dict]:
    """Formato baseline: attack;run;metric;value;unit."""
    rows: list[dict] = []
    try:
        with path.open(newline="") as f:
            reader = csv.DictReader(f, delimiter=";")
            for r in reader:
                value = to_float(r.get("value", ""))
                if value is None:
                    continue
                rows.append({
                    "attack": (r.get("attack") or default_attack or "").strip(),
                    "run":    int(str(r.get("run", "0")).strip() or "0"),
                    "metric": norm_metric(r.get("metric", "")),
                    "value":  value,
                    "unit":   (r.get("unit") or "").strip(),
                })
    except Exception as e:
        print(f"[AVISO] erro lendo {path}: {e}", file=sys.stderr)
    return rows


def parse_perf_native_csv(path: Path, attack: str, run: int) -> list[dict]:
    """Formato nativo perf stat -x ','. Linhas com '<not counted>' ou
    iniciadas por '#' são ignoradas."""
    rows: list[dict] = []
    try:
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 3:
                    continue
                value = to_float(parts[0])
                unit  = parts[1]
                event = norm_metric(parts[2])
                if value is None or not event:
                    continue
                rows.append({
                    "attack": attack, "run": run,
                    "metric": event, "value": value, "unit": unit,
                })
    except Exception as e:
        print(f"[AVISO] erro lendo {path}: {e}", file=sys.stderr)
    return rows


def parse_candump(
    path: Path,
    ids: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Lê log do candump -t a -L. Retorna DataFrame [ts, id, data].
    Filtra por IDs (case-insensitive, hex sem 0x) se fornecido."""
    if not path.is_file() or path.stat().st_size == 0:
        return pd.DataFrame(columns=["ts", "id", "data"])
    ids_norm = {i.upper() for i in ids} if ids else None
    rows = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            m = CANDUMP_RE.match(line)
            if not m:
                continue
            cid = m.group("id").upper()
            if ids_norm is not None and cid not in ids_norm:
                continue
            try:
                ts = float(m.group("ts"))
            except ValueError:
                continue
            rows.append((ts, cid, m.group("data").upper()))
    return pd.DataFrame(rows, columns=["ts", "id", "data"])


def parse_log_text(path: Path, patterns: dict[str, str]) -> dict[str, float]:
    """Aplica dict de regex em texto livre. Para cada chave 'metric':
    extrai o primeiro grupo capturado como float. Usado por
    parse_gateway_logs.py."""
    text = path.read_text(encoding="utf-8", errors="replace")
    out: dict[str, float] = {}
    for metric, regex in patterns.items():
        m = re.search(regex, text)
        if m:
            try:
                out[metric] = float(m.group(1))
            except ValueError:
                pass
    return out
