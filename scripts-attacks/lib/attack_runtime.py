# Runtime comum aos 4 ataques: abertura de socket CAN, loop com deadline,
# tratamento de CanError + KeyboardInterrupt, e relatório de fim de execução.

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

import can


@dataclass
class AttackStats:
    sent: int = 0
    errors: int = 0
    t_start: float = 0.0
    t_end: float = 0.0

    @property
    def elapsed(self) -> float:
        return self.t_end - self.t_start

    @property
    def fps(self) -> float:
        return self.sent / self.elapsed if self.elapsed > 0 else 0.0


def open_socketcan(iface: str) -> can.BusABC:
    """Abre socketcan via python-can — equivalente a
    can.interface.Bus(channel=iface, interface='socketcan')."""
    return can.interface.Bus(channel=iface, interface="socketcan")


def run_attack_loop(
    duration_s: float,
    bus: can.BusABC,
    next_message: Callable[[], can.Message],
    *,
    rate_ms: float = 0.0,
    swallow_send_errors: bool = True,
    on_iter: Optional[Callable[[int], None]] = None,
) -> AttackStats:
    """Loop de ataque com deadline. `next_message` produz o próximo frame
    (constante para DoS, sorteado para Fuzzy, função de target para Spoofing).

    - `rate_ms`: intervalo entre envios (0 = vazão máxima).
    - `swallow_send_errors`: True = ignora `CanError` (Fuzzy/Spoofing);
      False = imprime erro em stderr e dá break (DoS).
    - `on_iter`: callback opcional a cada envio (recebe count atualizado).

    Trata `KeyboardInterrupt` (mensagem em stderr) e `bus.shutdown()` no finally.
    Retorna stats parciais se interrompido.
    """
    stats = AttackStats(t_start=time.perf_counter())
    deadline = stats.t_start + duration_s
    interval_s = rate_ms / 1000.0
    try:
        while time.perf_counter() < deadline:
            msg = next_message()
            try:
                bus.send(msg)
                stats.sent += 1
            except can.CanError as e:
                stats.errors += 1
                if not swallow_send_errors:
                    print(f"[ERRO] Falha de transmissão: {e}", file=sys.stderr)
                    break
            if on_iter is not None:
                on_iter(stats.sent)
            if interval_s > 0:
                time.sleep(interval_s)
    except KeyboardInterrupt:
        print("\n[INFO] Interrompido pelo usuário.")
    finally:
        stats.t_end = time.perf_counter()
        bus.shutdown()
    return stats


def print_report(name: str, stats: AttackStats, *,
                 label: str = "Frames enviados",
                 extras: Iterable[str] = ()) -> None:
    """Imprime '[RESULTADO] <label>: N | Tempo: Xs | Taxa média: Y fps'
    com extras opcionais separados por ' | '."""
    line = (f"[RESULTADO] {label}: {stats.sent} | "
            f"Tempo: {stats.elapsed:.3f}s | "
            f"Taxa média: {stats.fps:.0f} fps")
    for x in extras:
        line += f" | {x}"
    print(line)
