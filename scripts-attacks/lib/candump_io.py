# Leitor e escritor do formato candump (-t a -L).
# Linha típica: (1747526400.123456) vcan0 244#01020304ABCDEF01
#
# Nota: a mesma regex existe em master-experiment/lib/perf_io.py.
# Repetida intencionalmente, domínios diferentes (análise estatística vs
# runtime de ataque) 

from __future__ import annotations

import re
from pathlib import Path
from typing import IO, Iterator, NamedTuple


CANDUMP_RE = re.compile(
    r"^\(\s*(?P<ts>[0-9]+\.[0-9]+)\)\s+(?P<iface>\S+)\s+"
    r"(?P<id>[0-9A-Fa-f]+)#(?P<data>[0-9A-Fa-f]*)\s*$"
)


class CandumpFrame(NamedTuple):
    ts: float
    iface: str
    arb_id: int
    data: bytes


def parse_line(line: str) -> CandumpFrame | None:
    """Parseia uma linha do candump. Retorna None se não casar."""
    m = CANDUMP_RE.match(line.strip())
    if not m:
        return None
    try:
        return CandumpFrame(
            ts=float(m.group("ts")),
            iface=m.group("iface"),
            arb_id=int(m.group("id"), 16),
            data=bytes.fromhex(m.group("data")) if m.group("data") else b"",
        )
    except ValueError:
        return None


def iter_candump(path: Path) -> Iterator[CandumpFrame]:
    """Itera frames de um log candump, pulando linhas inválidas."""
    with open(path) as f:
        for line in f:
            fr = parse_line(line)
            if fr is not None:
                yield fr


def write_line(f: IO[str], ts: float, iface: str,
               arb_id: int, data: bytes) -> None:
    """Escreve uma linha no formato candump -L (timestamp 6 casas,
    arb_id 3 dígitos hex maiúsculo, payload hex maiúsculo)."""
    f.write(f"({ts:.6f}) {iface} {arb_id:03X}#{data.hex().upper()}\n")
