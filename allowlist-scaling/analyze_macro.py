#!/usr/bin/env python3
"""
Análise do macro. Lê o perf_macro.csv (perf + contadores do gateway na mesma
chave) e produz:
  - ciclos/frame por célula (estratégia × N × ataque): mediana + IC95 (bootstrap);
  - análise de linear vs direct no mesmo (N, ataque)
  - ciclos/frame de I/O para a ponte com o micro (razão vs o limiar de 1%).

"""
from __future__ import annotations

import argparse
import csv
import random
import statistics as st
from collections import defaultdict

RNG = random.Random(42)


def boot_ci(xs, n=2000, alpha=0.05):
    """IC da mediana por bootstrap."""
    if len(xs) < 2:
        return (float("nan"), float("nan"))
    boots = sorted(st.median([xs[RNG.randrange(len(xs))] for _ in xs]) for _ in range(n))
    return boots[int(alpha / 2 * n)], boots[int((1 - alpha / 2) * n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--numerator", default="cycles", help="métrica do numerador")
    args = ap.parse_args()

    # (component, attack, run) -> {metric: value}
    cells = defaultdict(dict)
    for r in csv.DictReader(open(args.csv), delimiter=";"):
        try:
            cells[(r["component"], r["attack"], r["run"])][r["metric"]] = float(r["value"])
        except (KeyError, ValueError):
            continue

    # ciclos/frame por (component, attack)
    cpf = defaultdict(list)
    missing = 0
    for (comp, atk, _run), m in cells.items():
        num, rx = m.get(args.numerator), m.get("rx_total")
        if num is None or not rx:
            missing += 1
            continue
        cpf[(comp, atk)].append(num / rx)
    if missing:
        print(f"[aviso] {missing} rodada(s) sem {args.numerator}/rx_total — ignoradas.")

    # Tabela por célula
    print(f"\n{'component':14}{'attack':13}{'n':>3}{'mediana c/frame':>17}{'IC95':>24}")
    for k in sorted(cpf):
        xs = cpf[k]
        lo, hi = boot_ci(xs)
        print(f"{k[0]:14}{k[1]:13}{len(xs):>3}{st.median(xs):17.1f}   [{lo:9.1f},{hi:9.1f}]")

    # Teste do direct − linear no mesmo (N, ataque)
    print("\n=== Teste do nulo (direct − linear), mesmo N e ataque ===")
    Ns = sorted({c.split("-")[-1] for (c, _a) in cpf}, key=int)
    atks = sorted({a for (_c, a) in cpf})
    for N in Ns:
        for atk in atks:
            lin, dic = cpf.get((f"linear-{N}", atk)), cpf.get((f"direct-{N}", atk))
            if not lin or not dic:
                continue
            delta = st.median(dic) - st.median(lin)
            boots = sorted(st.median([dic[RNG.randrange(len(dic))] for _ in dic])
                           - st.median([lin[RNG.randrange(len(lin))] for _ in lin])
                           for _ in range(2000))
            lo, hi = boots[50], boots[-51]
            pct = 100 * delta / st.median(lin) if st.median(lin) else float("nan")
            verd = "nulo OK" if lo <= 0 <= hi else "DIFERE"
            print(f"  N={N:>3} {atk:12} Δ={delta:+8.1f} c/frame ({pct:+.2f}%)  "
                  f"IC95[{lo:+.1f},{hi:+.1f}] -> {verd}")

    # Número de I/O para a ponte com o micro
    print("\n=== Ciclos/frame de I/O para a ponte (analyze_micro --io-cycles-per-frame) ===")
    medians = {k: st.median(v) for k, v in cpf.items()}
    per_atk = defaultdict(list)
    for (comp, atk), xs in cpf.items():
        per_atk[atk].extend(xs)
    for atk in sorted(per_atk):
        print(f"  {atk:12} mediana global = {st.median(per_atk[atk]):.1f} c/frame")
    if medians:
        print(f"  {'conservador':12} MÍNIMO célula = {min(medians.values()):.1f} c/frame  "
              f"<- use este para o pior caso da razão")


if __name__ == "__main__":
    raise SystemExit(main())
