# Builders de frames CAN para o ICSim (zombieCraig/ICSim).
# IDs e layout dos payloads inferidos do simulador.

from __future__ import annotations

import can

# IDs do ICSim — carregados de lib/can_ids.py (raiz do repo).
# Nao usamos 'from lib.can_ids import ...' porque scripts-attacks/lib/
# ocupa o nome 'lib' no sys.path quando os ataques sao invocados.
import sys
from pathlib import Path

_REPO_LIB = Path(__file__).resolve().parents[2] / "lib"
if str(_REPO_LIB) not in sys.path:
    sys.path.insert(0, str(_REPO_LIB))

from can_ids import ID_SPEED, ID_SIGNAL, ID_DOORS  # noqa: E402


def build_speed_frame(kmh: int) -> can.Message:
    """Velocímetro: ICSim multiplica por ~100 e armazena em little-endian
    nos bytes 3-4 do payload de 8 bytes."""
    raw = max(0, min(int(kmh * 100), 0xFFFF))
    payload = bytearray(8)
    payload[3] = raw & 0xFF
    payload[4] = (raw >> 8) & 0xFF
    return can.Message(
        arbitration_id=ID_SPEED, data=bytes(payload), is_extended_id=False
    )


def build_signal_frame(left: bool, right: bool) -> can.Message:
    """Setas: byte 2 do payload — bit 0 = direita, bit 1 = esquerda."""
    payload = bytearray(8)
    payload[2] = (0x01 if right else 0) | (0x02 if left else 0)
    return can.Message(
        arbitration_id=ID_SIGNAL, data=bytes(payload), is_extended_id=False
    )


def build_doors_frame(mask: int) -> can.Message:
    """Portas: byte 2 — bits 0-3 = portas FL/FR/RL/RR."""
    payload = bytearray(8)
    payload[2] = mask & 0x0F
    return can.Message(
        arbitration_id=ID_DOORS, data=bytes(payload), is_extended_id=False
    )
