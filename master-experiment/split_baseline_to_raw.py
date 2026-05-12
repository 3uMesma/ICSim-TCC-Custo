# Lê o CSV unificado (formato canônico de lib/perf_csv.sh):
#     scenario;component;attack;run;metric;value;unit
# e gera um CSV por (attack, run) em <master-dir>/baseline/raw/<attack>_run<NN>.csv,
# no formato esperado por analyze_all.py:
#     attack;run;metric;value;unit
#
# Filtra apenas linhas com scenario == "baseline" e component == "process",
# que é o que o analyze_all.py espera (collect_baseline → component="process").

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.perf_io import CANONICAL_HEADER, RAW_HEADER


def split_baseline(master_dir: Path, csv_path: Path | None = None,
                   scenario_key: str = "baseline",
                   component_key: str = "process") -> int:
    """
    Divide o CSV unificado em arquivos por (attack, run).
    Retorna o número de arquivos escritos.
    """
    csv_path = csv_path or (master_dir / "perf_data.csv")
    if not csv_path.is_file():
        print(f"[erro] CSV unificado não encontrado: {csv_path}", file=sys.stderr)
        return 0

    raw_dir = master_dir / "baseline" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # Agrupa as linhas por (attack, run) — mantém a ordem de leitura.
    buckets: dict[tuple[str, int], list[dict]] = defaultdict(list)

    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f, delimiter=";")
        # Sanidade: confirma que o header do CSV bate com o canônico.
        if reader.fieldnames != CANONICAL_HEADER:
            print(f"[aviso] header inesperado em {csv_path}: {reader.fieldnames}",
                  file=sys.stderr)
            print(f"        esperado: {CANONICAL_HEADER}", file=sys.stderr)
            # Continua mesmo assim — pode haver colunas extras que não atrapalham.

        for row in reader:
            if (row.get("scenario") or "").strip() != scenario_key:
                continue
            if (row.get("component") or "").strip() != component_key:
                continue

            attack = (row.get("attack") or "").strip()
            run_s = (row.get("run") or "").strip()
            if not attack or not run_s:
                continue
            try:
                run = int(run_s)
            except ValueError:
                continue

            buckets[(attack, run)].append({
                "attack": attack,
                "run": run,
                "metric": (row.get("metric") or "").strip(),
                "value": (row.get("value") or "").strip(),
                "unit": (row.get("unit") or "").strip(),
            })

    if not buckets:
        print(f"[aviso] nenhuma linha com scenario={scenario_key!r} e "
              f"component={component_key!r} encontrada em {csv_path}.",
              file=sys.stderr)
        return 0

    # Escreve um arquivo por (attack, run). Convenção do analyze_all.py:
    # <attack>_run<NN>.csv (zero-padding em 2 dígitos).
    n_written = 0
    for (attack, run), rows in sorted(buckets.items()):
        out_path = raw_dir / f"{attack}_run{run:02d}.csv"
        with out_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=RAW_HEADER, delimiter=";")
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        n_written += 1

    print(f"[ok] {n_written} arquivo(s) escrito(s) em {raw_dir}/")
    return n_written


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Split do perf_data.csv unificado em "
                    "<master-dir>/baseline/raw/<attack>_run<NN>.csv "
                    "(formato esperado por analyze_all.py).")
    ap.add_argument("--master-dir", required=True, type=Path,
                    help="Diretório master_results/<timestamp> da campanha.")
    ap.add_argument("--csv", type=Path, default=None,
                    help="Caminho do CSV unificado "
                         "(default: <master-dir>/perf_data.csv).")
    ap.add_argument("--scenario", default="baseline",
                    help="Cenário a filtrar (default: baseline).")
    ap.add_argument("--component", default="process",
                    help="Componente a filtrar (default: process).")
    args = ap.parse_args()

    if not args.master_dir.is_dir():
        print(f"[erro] master-dir não existe: {args.master_dir}", file=sys.stderr)
        return 2

    n = split_baseline(args.master_dir, args.csv,
                       scenario_key=args.scenario,
                       component_key=args.component)
    return 0 if n > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
