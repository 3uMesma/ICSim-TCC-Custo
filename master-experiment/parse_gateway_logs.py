# Cada rodada (cenário 2 e 3) gera um relatório textual produzido pelo 
# gateway/sender em C, contendo contadores como: Duração de execução, 
# Frames recebidos em vcan0, Frames autenticados (FWD), Rejeições por 
# ID desconhecido, Rejeições por MAC, Throughput médio do gateway
#
from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

# Padrões regex — robustos a diferentes versões do gateway/sender:
# capturam o último número da linha após uma sequência de '.' decorativos.
_NUM = r"([0-9]+(?:\.[0-9]+)?)"

PATTERNS_GATEWAY_CEN2 = {
    "duration_s":       rf"Duração de execução\s+\.+\s+{_NUM}\s*s",
    "rx_total":         rf"Frames recebidos em vcan0\s+\.+\s+{_NUM}",
    "fwd_total":        rf"Frames liberados\s+\.+\s+{_NUM}",
    "blocked_id":       rf"Frames bloqueados \(ID\)\s+\.+\s+{_NUM}",
    "blocked_dlc":      rf"Frames bloqueados \(DLC\)\s+\.+\s+{_NUM}",
    "blocked_rate":     rf"Frames bloqueados \(rate\)\s+\.+\s+{_NUM}",
    "throughput_fps":   rf"Throughput médio do gateway\s+\.+\s+{_NUM}\s*frames/s",
}

# Passthrough do baseline emite o mesmo formato do gateway cen2 (com todos
# os blocked_* zerados, porque não aplica nenhuma política). Mantemos um
# PATTERNS dedicado para clareza
PATTERNS_PASSTHROUGH = {
    "duration_s":       rf"Duração de execução\s+\.+\s+{_NUM}\s*s",
    "rx_total":         rf"Frames recebidos em vcan0\s+\.+\s+{_NUM}",
    "fwd_total":        rf"Frames liberados\s+\.+\s+{_NUM}",
    "blocked_id":       rf"Frames bloqueados \(ID\)\s+\.+\s+{_NUM}",
    "blocked_dlc":      rf"Frames bloqueados \(DLC\)\s+\.+\s+{_NUM}",
    "blocked_rate":     rf"Frames bloqueados \(rate\)\s+\.+\s+{_NUM}",
    "throughput_fps":   rf"Throughput médio do gateway\s+\.+\s+{_NUM}\s*frames/s",
}

PATTERNS_GATEWAY_CEN3 = {
    "duration_s":       rf"Duração de execução\s+\.+\s+{_NUM}\s*s",
    "rx_total":         rf"Frames recebidos em vcan0\s+\.+\s+{_NUM}",
    "fwd_total":        rf"Frames autenticados \(FWD\)\s+\.+\s+{_NUM}",
    "secoc_ok":         rf"Verdicts SECOC_OK \(pré-write\)\s+\.+\s+{_NUM}",
    "blocked_id":       rf"Rejeições por ID desconhecido\s+\.+\s+{_NUM}",
    "blocked_dlc":      rf"Rejeições por DLC\s+\.+\s+{_NUM}",
    "blocked_fv":       rf"Rejeições por FV \(freshness\)\s+\.+\s+{_NUM}",
    "blocked_mac":      rf"Rejeições por MAC\s+\.+\s+{_NUM}",
    "blocked_eff":      rf"Rejeições por EFF/CAN-FD\s+\.+\s+{_NUM}",
    "throughput_fps":   rf"Throughput médio do gateway\s+\.+\s+{_NUM}\s*frames/s",
}

PATTERNS_SENDER = {
    "duration_s":           rf"Duração de execução\s+\.+\s+{_NUM}\s*s",
    "read":                 rf"Frames lidos em vcan_trust\s+\.+\s+{_NUM}",
    "authenticated_tx":     rf"Frames autenticados \(TX\)\s+\.+\s+{_NUM}",
    "discarded":            rf"Frames descartados \(ID/LEN\)\s+\.+\s+{_NUM}",
    "throughput_fps":       rf"Throughput médio de autenticação\s+\.+\s+{_NUM}\s*frames/s",
}


sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.perf_io import parse_log_text as parse_log


def parse_run_dir_name(dirname: str) -> tuple[str, int] | None:
    """
    Aceita nomes do tipo:
      dos-py_run01
      dos-cangen_run17
      replay_run20
    Retorna (attack, run_int) ou None se não casar.
    """
    m = re.match(r"^(?P<attack>[a-z][a-z0-9-]+)_run(?P<run>\d+)$", dirname)
    if not m:
        return None
    return m.group("attack"), int(m.group("run"))


def collect_baseline(master: Path, rows: list[dict]) -> int:
    """Varre baseline/runs/*/passthrough.log e adiciona linhas tidy a `rows`.

    Cada execução de run_passthrough.sh produz um relatório textual no
    mesmo formato do cen2 (gateway sem política). Aqui apenas etiquetamos
    component='passthrough' para distinguir do gateway de cen2 quando o
    CSV combinado for consumido pelas análises.
    """
    base = master / "baseline" / "runs"
    if not base.is_dir():
        return 0
    n = 0
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        info = parse_run_dir_name(d.name)
        if info is None:
            continue
        attack, run = info
        pt = d / "passthrough.log"
        if not pt.is_file():
            continue
        data = parse_log(pt, PATTERNS_PASSTHROUGH)
        for metric, value in data.items():
            rows.append({
                "scenario": "baseline", "attack": attack, "run": run,
                "component": "passthrough", "metric": metric, "value": value,
            })
        n += 1
    return n


def collect_cen2(master: Path, rows: list[dict]) -> int:
    """Varre cenario2/runs/* e adiciona linhas tidy a `rows`. Retorna contagem."""
    base = master / "cenario2" / "runs"
    if not base.is_dir():
        return 0
    n = 0
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        info = parse_run_dir_name(d.name)
        if info is None:
            continue
        attack, run = info
        gw = d / "gateway.log"
        if not gw.is_file():
            continue
        data = parse_log(gw, PATTERNS_GATEWAY_CEN2)
        for metric, value in data.items():
            rows.append({
                "scenario": "cen2", "attack": attack, "run": run,
                "component": "gateway", "metric": metric, "value": value,
            })
        n += 1
    return n


def collect_cen3(master: Path, rows: list[dict]) -> int:
    """
    Varre cenario3/* (sem subpasta runs/) e adiciona gateway + sender.
    Retorna contagem total de pastas processadas.
    """
    base = master / "cenario3"
    if not base.is_dir():
        return 0
    n = 0
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        info = parse_run_dir_name(d.name)
        if info is None:
            continue
        attack, run = info
        gw = d / "gateway.log"
        if gw.is_file():
            data = parse_log(gw, PATTERNS_GATEWAY_CEN3)
            for metric, value in data.items():
                rows.append({
                    "scenario": "cen3", "attack": attack, "run": run,
                    "component": "gateway", "metric": metric, "value": value,
                })
        sd = d / "sender.log"
        if sd.is_file():
            data = parse_log(sd, PATTERNS_SENDER)
            for metric, value in data.items():
                rows.append({
                    "scenario": "cen3", "attack": attack, "run": run,
                    "component": "sender", "metric": metric, "value": value,
                })
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extrai contadores de carga dos logs do gateway/sender "
                    "para CSV tidy (uma linha por métrica)."
    )
    ap.add_argument("--master-dir", type=Path, required=True,
                    help="Diretório resultados/<timestamp>/")
    ap.add_argument("--out", type=Path, default=None,
                    help="CSV de saída (default: <master-dir>/gateway_logs.csv)")
    args = ap.parse_args()

    master = args.master_dir.resolve()
    if not master.is_dir():
        print(f"[ERRO] diretório não encontrado: {master}", file=sys.stderr)
        return 1

    out_path = args.out or (master / "gateway_logs.csv")
    rows: list[dict] = []

    n1 = collect_baseline(master, rows)
    n2 = collect_cen2(master, rows)
    n3 = collect_cen3(master, rows)

    if not rows:
        print("[ERRO] nenhum log parseado — verifique a estrutura da pasta.",
              file=sys.stderr)
        return 2

    fieldnames = ["scenario", "attack", "run", "component", "metric", "value"]
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        w.writeheader()
        w.writerows(rows)

    # Sumário
    print(f"  baseline runs parseadas : {n1}")
    print(f"  cen2 runs parseadas     : {n2}")
    print(f"  cen3 runs parseadas     : {n3}")
    print(f"  linhas no CSV       : {len(rows):,}")
    print(f"  arquivo escrito     : {out_path}")

    # Contagem de cobertura por (cenário, ataque)
    coverage: dict[tuple[str, str, str], int] = {}
    for r in rows:
        k = (r["scenario"], r["component"], r["attack"])
        coverage[k] = coverage.get(k, 0) + 1
    print("\n  cobertura (linhas por scenario|component|attack):")
    for k in sorted(coverage):
        print(f"    {k[0]:>6} {k[1]:>8} {k[2]:>10}  : {coverage[k]:4d} linhas")

    return 0


if __name__ == "__main__":
    sys.exit(main())
