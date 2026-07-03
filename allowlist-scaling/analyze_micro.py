#!/usr/bin/env python3
"""
Analisa o micro.csv do microbenchmark de lookup.

  1) agrega: mediana + IC95 por (estratégia, N, path);
  2) ajusta custo(N): linear a+b*N, binary a+b*log2(N), direct/baseline const;
  3) acha cruzamentos entre estratégias;
  4) dado o custo de I/O por frame (do macro), calcula a razão do argumento
     "desprezível" e compara ao limiar de 1%.

Uso:
  python3 analyze_micro.py micro.csv [--io-cycles-per-frame X] [--plot fig.png]
"""
import argparse
import csv
import math
import statistics as st
from collections import defaultdict

STRATS = ("linear", "binary", "direct")


def load(path):
    d = defaultdict(list)
    for r in csv.DictReader(open(path)):
        d[(r["strategy"], int(r["N"]), r["path"])].append(float(r["cycles_per_lookup"]))
    return d


def ic95(v):
    n = len(v)
    return 1.96 * st.pstdev(v) / math.sqrt(n) if n > 1 else 0.0


def lsq(xs, ys):
    """y = a + b*x por mínimos quadrados; retorna a, b, R²."""
    n = len(xs); sx = sum(xs); sy = sum(ys)
    sxx = sum(x * x for x in xs); sxy = sum(x * y for x, y in zip(xs, ys))
    b = (n * sxy - sx * sy) / (n * sxx - sx * sx)
    a = (sy - b * sx) / n
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - sy / n) ** 2 for y in ys)
    return a, b, (1 - ss_res / ss_tot if ss_tot else 1.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--io-cycles-per-frame", type=float, default=None,
                    help="ciclos de I/O por frame (do macro) para a razão")
    ap.add_argument("--threshold", type=float, default=0.01, help="limiar (default 1%)")
    ap.add_argument("--plot", help="salva figura ciclos/lookup vs N (PNG)")
    args = ap.parse_args()

    d = load(args.csv)
    Ns = sorted({N for _, N, _ in d})
    Nmax = Ns[-1]

    # 1) agregado
    print("== Agregado (mediana [IC95]) ==")
    print(f"{'strat':8}{'N':>5} {'path':5}{'mediana':>9}{'IC95±':>8}")
    order = {"baseline": 0, "linear": 1, "binary": 2, "direct": 3}
    for k in sorted(d, key=lambda x: (x[1], order[x[0]], x[2])):
        v = d[k]
        print(f"{k[0]:8}{k[1]:>5} {k[2]:5}{st.median(v):9.2f}{ic95(v):8.2f}")

    # 2) ajustes custo(N) por (estratégia, path)
    def med(s, p, N):
        return st.median(d[(s, N, p)])

    print("\n== Ajuste custo(N) por estratégia (path=miss, pior caso) ==")
    fits = {}
    for s in STRATS:
        ys = [med(s, "miss", N) for N in Ns]
        if s == "linear":
            a, b, r2 = lsq(Ns, ys)
            fits[s] = ("N", a, b)
            print(f"linear: custo ≈ {a:.1f} + {b:.3f}·N   (R²={r2:.3f})  [+{b:.3f} ciclo/entrada]")
        elif s == "binary":
            a, b, r2 = lsq([math.log2(N) for N in Ns], ys)
            fits[s] = ("log2N", a, b)
            print(f"binary: custo ≈ {a:.1f} + {b:.2f}·log2(N)   (R²={r2:.3f})")
        else:
            c = st.mean(ys)
            fits[s] = ("const", c, 0.0)
            print(f"direct: custo ≈ {c:.2f} (constante, O(1))")

    # 3) cruzamentos (no path miss)
    print("\n== Cruzamentos (miss) ==")
    la, lb = fits["linear"][1], fits["linear"][2]
    dc = fits["direct"][1]
    n_ld = (dc - la) / lb
    print(f"linear vs direct: linear passa direct em N≈{n_ld:.0f}"
          + ("  (i.e., direct sempre ≤ linear)" if n_ld < 1 else ""))
    # linear vs binary: varre N até linear <= binary deixar de valer
    ba, bb = fits["binary"][1], fits["binary"][2]
    cross = None
    for N in range(1, 4096):
        lin = la + lb * N
        binv = ba + bb * math.log2(N)
        if lin > binv:
            cross = N
            break
    if cross is None or cross <= 1:
        print("linear vs binary: binary ≤ linear em todo N mensurável")
    else:
        print(f"linear vs binary: linear é mais barato só até N≈{cross}")

    # 4) ponte para o I/O
    worst = med("linear", "miss", Nmax)
    best = med("direct", "miss", Nmax)
    print(f"\n== Ponte para o I/O (pior caso = linear miss N={Nmax} ≈ {worst:.0f} ciclos) ==")
    if args.io_cycles_per_frame:
        io = args.io_cycles_per_frame
        r_worst = worst / io
        r_best = best / io
        print(f"I/O por frame = {io:.0f} ciclos")
        print(f"razão pior caso (linear/{Nmax}): {100*r_worst:.3f}%  "
              f"{'<' if r_worst < args.threshold else '>='} {100*args.threshold:.0f}%  "
              f"→ {'DESPREZÍVEL' if r_worst < args.threshold else 'NÃO passa o limiar'}")
        print(f"razão melhor caso (direct):     {100*r_best:.4f}%")
    else:
        print("razão pendente — rode o macro e passe --io-cycles-per-frame X")

    if args.plot:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6, 4))
        for s in STRATS:
            for p, ls in (("hit", "--"), ("miss", "-")):
                ax.plot(Ns, [med(s, p, N) for N in Ns], ls, marker="o", label=f"{s} {p}")
        ax.set_xlabel("N (tamanho da allowlist)"); ax.set_ylabel("ciclos por lookup")
        ax.set_xscale("log", base=2); ax.legend(fontsize=8); ax.grid(True, alpha=0.3)
        fig.tight_layout(); fig.savefig(args.plot, dpi=130)
        print(f"\nfigura -> {args.plot}")


if __name__ == "__main__":
    main()
