#!/usr/bin/env python3
"""
Transmitir quadros CAN com IDs e payloads aleatórios para
provocar comportamentos imprevistos em ECUs
"""
import argparse
import random
import sys
import time
import can


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fuzzing de barramento CAN")
    p.add_argument("--iface", default="vcan0")
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument("--rate", type=float, default=1.0,
                   help="Intervalo médio entre frames em ms (default: 1.0)")
    # --seed permite repetição exata do experimento entre execuções
    p.add_argument("--seed", type=int, default=42,
                   help="Semente do PRNG para reprodutibilidade")
    p.add_argument("--id-min", type=lambda x: int(x, 0), default=0x000)
    p.add_argument("--id-max", type=lambda x: int(x, 0), default=0x7FF,
                   help="Limite superior do ID (0x7FF para CAN 11-bit)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)
    bus = can.interface.Bus(channel=args.iface, interface="socketcan")

    print(f"[INFO] Iniciando Fuzzing em {args.iface} | "
          f"ID∈[0x{args.id_min:03X}, 0x{args.id_max:03X}] | "
          f"seed={args.seed} | duração={args.duration}s")

    sent = 0
    t0 = time.perf_counter()
    deadline = t0 + args.duration
    interval_s = args.rate / 1000.0

    try:
        while time.perf_counter() < deadline:
            arb_id = rng.randint(args.id_min, args.id_max)
            dlc = rng.randint(0, 8)
            data = bytes(rng.randint(0, 255) for _ in range(dlc))
            msg = can.Message(arbitration_id=arb_id, data=data,
                              is_extended_id=False)
            try:
                bus.send(msg)
                sent += 1
            except can.CanError:
                pass  # buffer cheio - descartar e continuar estresse
            if interval_s > 0:
                time.sleep(interval_s)
    except KeyboardInterrupt:
        print("\n[INFO] Interrompido pelo usuário.")
    finally:
        elapsed = time.perf_counter() - t0
        bus.shutdown()
        print(f"[RESULTADO] Frames enviados: {sent} | "
              f"Tempo: {elapsed:.3f}s | "
              f"Taxa média: {sent/elapsed:.0f} fps")


if __name__ == "__main__":
    main()
