#!/usr/bin/env python3
"""
Gera as tabelas de allowlist a partir dos IDs reais extraídos da HCRL.

Como a estratégia O(1) escolhida é índice-direto (e não hash ingênua), 
o custo de busca depende apenas da quantidade e ordem. Logo o padding só 
precisa ser: IDs de 11 bits DISTINTOS, NÃO-COLIDIDOS, e gerados com SEED 
FIXA para reprodutibilidade. 

Constrói dois arranjos ordenados de comprimento N_max; a tabela de tamanho N
é o prefixo de N elementos do arranjo. O papel de cada arranjo é:

  MICRO = [27 IDs reais da HCRL] + [padding sintético]
  MACRO = [3 IDs do ICSim] + [27 IDs reais como padding realista] + [sintético]

Assim: no micro a tabela sempre contém os 27 reais; no macro sempre contém os
3 do ICSim (para o tráfego legítimo passar), e o restante é peso-morto que só
alonga a varredura de miss sob DoS/fuzzing — o pior caso do linear.

"""
from __future__ import annotations
 
import argparse
import random
import re
import sys
from pathlib import Path
 
ID_TOKEN = re.compile(r"0x[0-9A-Fa-f]+", re.ASCII)
 
 
def parse_ids(path: Path) -> list[int]:
    return [int(t, 16) for t in ID_TOKEN.findall(path.read_text(errors="replace"))]
 
 
def parse_id_list(spec: str) -> list[int]:
    return [int(tok, 16) for tok in spec.split(",") if tok.strip()]
 
 
def build_sweep(n_max: int, n_real: int) -> list[int]:
    pts, p = [n_real], 32
    while p <= n_max:
        if p > n_real:
            pts.append(p)
        p *= 2
    if pts[-1] != n_max:
        pts.append(n_max)
    return sorted(set(pts))
 
 
def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("real_ids", type=Path, help="arquivo com os IDs reais")
    ap.add_argument("--n-max", type=int, default=256)
    ap.add_argument("--sweep", default="", help="lista explícita de N; vazio = auto")
    ap.add_argument("--icsim", default="0x244,0x188,0x19B")
    ap.add_argument("--exclude", default="0x000")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--bits", type=int, choices=(11, 29), default=11)
    ap.add_argument("--header-out", type=Path, default=Path("allowlist_sweep.h"))
    ap.add_argument("--manifest-out", type=Path, default=Path("padding_manifest.csv"))
    args = ap.parse_args()
 
    width = 3 if args.bits == 11 else 8
    space = 1 << args.bits
 
    real = parse_ids(args.real_ids)
    icsim = parse_id_list(args.icsim)
    exclude = set(parse_id_list(args.exclude))
    n_real = len(real)
 
    sweep = (sorted({int(x) for x in args.sweep.split(",") if x.strip()})
             if args.sweep.strip() else build_sweep(args.n_max, n_real))
    n_max = max(sweep)
 
    pool = [v for v in range(space) if v not in (set(real) | set(icsim) | exclude)]
    synth = random.Random(args.seed).sample(pool, n_max)  # determinístico
 
    micro = (real + synth)[:n_max]
    macro = (icsim + real + synth)[:n_max]
 
    # Sem IDs repetidos
    assert len(set(micro)) == n_max and len(set(macro)) == n_max, "IDs repetidos"
 
    def hx(v: int) -> str:
        return f"0x{v:0{width}X}"
 
    def emit_array(name, arr):
        body = ",\n    ".join(hx(v) for v in arr)
        return f"static const canid_t {name}[{len(arr)}] = {{\n    {body}\n}};\n"
 
    with args.header_out.open("w") as fh:
        fh.write(f"/* synth_padding.py — seed={args.seed}, bits={args.bits}, "
                 f"N_max={n_max}, N_real={n_real}. Tabela de tamanho N = primeiros N. "
                 f"Requer canid_t (linux/can.h). */\n")
        fh.write("#ifndef ALLOWLIST_SWEEP_H\n#define ALLOWLIST_SWEEP_H\n\n")
        fh.write(f"#define SWEEP_N_MAX {n_max}\n")
        fh.write(f"#define SWEEP_COUNT {len(sweep)}\n")
        fh.write("static const int g_sweep_sizes[SWEEP_COUNT] = {"
                 + ",".join(map(str, sweep)) + "};\n\n")
        fh.write(f"#define MICRO_LEN {len(micro)}\n" + emit_array("g_micro_ids", micro))
        fh.write(f"\n#define MACRO_LEN {len(macro)}\n" + emit_array("g_macro_ids", macro))
        fh.write("\n#endif /* ALLOWLIST_SWEEP_H */\n")
 
    with args.manifest_out.open("w") as fh:
        fh.write("role,index,can_id_hex,origin\n")
        icsim_set, real_set = set(icsim), set(real)
        for role, arr in (("micro", micro), ("macro", macro)):
            for i, v in enumerate(arr):
                origin = "icsim" if v in icsim_set else "real" if v in real_set else "synth"
                fh.write(f"{role},{i},{hx(v)},{origin}\n")
 
    print(f"N_real={n_real} sweep={sweep} -> {args.header_out}, {args.manifest_out}",
          file=sys.stderr)
    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(main())