#!/usr/bin/env python3
"""
Transmitir quadros CAN com IDs e payloads aleatórios para
provocar comportamentos imprevistos em ECUs.
"""

import argparse
import random
import sys
from pathlib import Path

import can

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.attack_runtime import open_socketcan, run_attack_loop, print_report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fuzzing de barramento CAN")
    p.add_argument("--iface", default="vcan0")
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument(
        "--rate",
        type=float,
        default=1.0,
        help="Intervalo médio entre frames em ms (default: 1.0)",
    )
    # --seed permite repetição exata do experimento entre execuções
    p.add_argument(
        "--seed", type=int, default=42, help="Semente do PRNG para reprodutibilidade"
    )
    p.add_argument("--id-min", type=lambda x: int(x, 0), default=0x000)
    p.add_argument(
        "--id-max",
        type=lambda x: int(x, 0),
        default=0x7FF,
        help="Limite superior do ID (0x7FF para CAN 11-bit)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)
    bus = open_socketcan(args.iface)

    print(
        f"[INFO] Iniciando Fuzzing em {args.iface} | "
        f"ID∈[0x{args.id_min:03X}, 0x{args.id_max:03X}] | "
        f"seed={args.seed} | duração={args.duration}s"
    )

    # next_message fecha sobre rng — ordem das chamadas rng.randint
    # (id, dlc, depois byte-a-byte do payload) é o que mantém determinismo
    # com --seed. NÃO trocar a ordem.
    def next_message() -> can.Message:
        arb_id = rng.randint(args.id_min, args.id_max)
        dlc = rng.randint(0, 8)
        data = bytes(rng.randint(0, 255) for _ in range(dlc))
        return can.Message(arbitration_id=arb_id, data=data, is_extended_id=False)

    stats = run_attack_loop(
        args.duration, bus, next_message,
        rate_ms=args.rate, swallow_send_errors=True,
    )
    print_report("Fuzzy", stats)


if __name__ == "__main__":
    main()
