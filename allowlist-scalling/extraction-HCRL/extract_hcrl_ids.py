"""
Extrai os IDs CAN legítimos da captura normal da HCRL para ancorar a allowlist.

Formato esperado (candump-text, normal_run_data.txt), uma linha por frame:
  (1479121434.850202) can0 0316#0520C1140010001C

Saída: IDs distintos ordenados (hex, 11 bits) no stdout; --header-out grava o
trecho C. Exclui 0x000 (sentinela/DoS) e o que vier em --exclude.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# (ts) iface  ID#DATA
FRAME = re.compile(r"^\(\s*[\d.]+\s*\)\s+\S+\s+([0-9A-Fa-f]{1,8})#", re.ASCII)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", type=Path, help="captura(s) normal(is) da HCRL")
    ap.add_argument("--exclude", default="0x000", help="IDs hex a excluir")
    ap.add_argument("--header-out", type=Path, help="grava trecho C com o array de IDs")
    args = ap.parse_args()

    exclude = {int(t, 16) for t in args.exclude.split(",") if t.strip()}

    ids: set[int] = set()
    for p in args.files:
        for line in p.open(errors="replace"):
            m = FRAME.match(line)
            if m:
                cid = int(m.group(1), 16)
                if cid not in exclude:
                    ids.add(cid)

    ids_sorted = sorted(ids)
    for v in ids_sorted:
        print(f"0x{v:03X}")
    print(f"[info] N_real = {len(ids_sorted)} IDs distintos", file=sys.stderr)

    if args.header_out:
        body = ",\n    ".join(f"0x{v:03X}" for v in ids_sorted)
        args.header_out.write_text(
            f"/* extract_hcrl_ids.py — N_real = {len(ids_sorted)} */\n"
            f"#define HCRL_N_REAL {len(ids_sorted)}\n"
            f"static const canid_t g_hcrl_ids[HCRL_N_REAL] = {{\n    {body}\n}};\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())