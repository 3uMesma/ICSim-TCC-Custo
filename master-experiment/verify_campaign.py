# Audita a integridade de uma campanha (process-attached ou system-wide)
# lendo o `master_log.txt` da pasta de resultados e contando rodadas
# concluídas, avisos e erros.
#
# Critérios:
#   - rodada [ok]    : linha contém "[ok]" (escrita pelos run_*.sh)
#   - aviso          : linha contém "[AVISO]" ou "WARN" (case-insensitive)
#                      EXCLUINDO o aviso preventivo de perf_event_paranoid
#                      (informativo, não impeditivo)
#   - erro funcional : linha contém "[ERRO]", "[erro]", " ERROR " ou
#                      "falhou" (substring), excluindo "pode falhar"
#                      (que é a frase do aviso preventivo)
#
# Exit code 0 se "Status global == OK", 1 caso contrário

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


# Padrões compilados — case-insensitive onde aplicável.
RE_OK    = re.compile(r"\[ok\]", re.IGNORECASE)
RE_AVISO = re.compile(r"\[AVISO\]|\bWARN(ING)?\b", re.IGNORECASE)
RE_ERRO  = re.compile(r"\[ERRO\]|\[erro\]|\bERROR\b", re.IGNORECASE)
RE_FALH  = re.compile(r"\bfalh", re.IGNORECASE)

# Frases que parecem aviso/erro mas são informativas/preventivas.
# Mantemos elas no CSV de auditoria mas NÃO contam para o status global.
WHITELIST_PATTERNS = [
    re.compile(r"perf_event_paranoid", re.IGNORECASE),
    re.compile(r"pode falhar", re.IGNORECASE),   # frase do aviso acima
    re.compile(r"DtypeWarning",  re.IGNORECASE), # warning do pandas no plot
]


@dataclass
class CampaignReport:
    log_path: str
    total_lines: int
    n_ok: int
    n_aviso: int
    n_erro: int
    n_falh: int
    n_aviso_whitelisted: int
    n_erro_whitelisted: int
    status: str          # "OK" ou "FALHA"
    samples_aviso: list[str]
    samples_erro: list[str]


def is_whitelisted(line: str) -> bool:
    return any(p.search(line) for p in WHITELIST_PATTERNS)


def audit_log(log_path: Path,
              n_samples: int = 5) -> CampaignReport:
    """Lê master_log.txt linha a linha e classifica."""
    total = 0
    n_ok = 0
    n_aviso = 0
    n_erro = 0
    n_falh = 0
    n_aviso_wl = 0
    n_erro_wl = 0
    samples_aviso: list[str] = []
    samples_erro: list[str] = []

    with log_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            total += 1
            line = line.rstrip("\n")
            is_wl = is_whitelisted(line)
            if RE_OK.search(line):
                n_ok += 1
            if RE_AVISO.search(line):
                if is_wl:
                    n_aviso_wl += 1
                else:
                    n_aviso += 1
                    if len(samples_aviso) < n_samples:
                        samples_aviso.append(line.strip())
            if RE_ERRO.search(line):
                if is_wl:
                    n_erro_wl += 1
                else:
                    n_erro += 1
                    if len(samples_erro) < n_samples:
                        samples_erro.append(line.strip())
            if RE_FALH.search(line) and not is_wl:
                # "falh" sem whitelist é forte indício de erro funcional
                n_falh += 1
                if len(samples_erro) < n_samples:
                    samples_erro.append(line.strip())

    status = "OK" if (n_erro == 0 and n_falh == 0) else "FALHA"
    return CampaignReport(
        log_path=str(log_path),
        total_lines=total,
        n_ok=n_ok,
        n_aviso=n_aviso,
        n_erro=n_erro,
        n_falh=n_falh,
        n_aviso_whitelisted=n_aviso_wl,
        n_erro_whitelisted=n_erro_wl,
        status=status,
        samples_aviso=samples_aviso,
        samples_erro=samples_erro,
    )


def print_report(report: CampaignReport, label: str = "") -> None:
    head = f"Auditoria — {label or report.log_path}"
    print("=" * 68)
    print(f"  {head}")
    print("=" * 68)
    print(f"  Linhas totais         : {report.total_lines:>6,}")
    print(f"  Rodadas marcadas [ok] : {report.n_ok:>6,}")
    print(f"  Avisos significativos : {report.n_aviso:>6,}"
          f"  (whitelisted: {report.n_aviso_whitelisted})")
    print(f"  Erros funcionais      : {report.n_erro:>6,}"
          f"  (whitelisted: {report.n_erro_whitelisted})")
    print(f"  Linhas 'falh...'      : {report.n_falh:>6,}")
    print(f"  STATUS GLOBAL         : {report.status}")
    if report.samples_aviso:
        print("\n  Primeiros avisos não-whitelisted:")
        for s in report.samples_aviso:
            print(f"    > {s}")
    if report.samples_erro:
        print("\n  Primeiros erros:")
        for s in report.samples_erro:
            print(f"    > {s}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Audita master_log.txt de uma campanha e relata "
                    "integridade (rodadas OK, avisos, erros funcionais)."
    )
    ap.add_argument("--master-dir", type=Path, required=True,
                    help="Diretório resultados/<timestamp>/ ou "
                         "resultados-sw/<timestamp>/")
    ap.add_argument("--label", default="",
                    help="Rótulo informativo no cabeçalho do relatório.")
    ap.add_argument("--out", type=Path, default=None,
                    help="Salva resumo em CSV (uma linha por campanha).")
    args = ap.parse_args()

    master = args.master_dir.resolve()
    log = master / "master_log.txt"
    if not log.is_file():
        print(f"[ERRO] {log} não encontrado.", file=sys.stderr)
        return 2

    label = args.label or master.name
    report = audit_log(log)
    print_report(report, label=label)

    if args.out:
        flat = asdict(report)
        flat["samples_aviso"] = " | ".join(report.samples_aviso)
        flat["samples_erro"]  = " | ".join(report.samples_erro)
        write_header = not args.out.exists() or args.out.stat().st_size == 0
        with args.out.open("a", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(flat.keys()))
            if write_header:
                w.writeheader()
            w.writerow(flat)
        print(f"  CSV: {args.out}")

    return 0 if report.status == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
