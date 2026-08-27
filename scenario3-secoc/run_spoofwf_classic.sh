#!/usr/bin/env bash
# Campanha minima do spoof bem-formado — perfil CLASSICO (CAN 2.0), 
#   hit  = ID 0x244 (associado)  -> chega ao MAC
#   miss = ID 0x555 (nao assoc.) -> morre no ID = linha de base de I/O, mesmo tamanho
# custo do MAC/frame = ciclos/frame(hit) - ciclos/frame(miss).
#
set -euo pipefail
cd "$(dirname "$0")"

CSV="$PWD/results/perf_spoofwf_classic.csv"
REPS="${REPS:-20}"
GW="$PWD/secoc_gateway"                          # build classico (make all)
SPOOF="$PWD/../scripts-attacks/spoof_wellformed_classic"

mkdir -p "$PWD/results"
echo "[campanha] gateway=$GW  reps=$REPS  (perfil classico CAN 2.0)"
echo "[campanha] atacante=$SPOOF"
echo "[campanha] csv=$CSV"

for r in $(seq 1 "$REPS"); do
    echo "===== rep $r / $REPS ====="
    COMPONENT=hit  SPOOF_ID=0x244 SPOOF_PLAIN_LEN=5 SPOOF_OVERHEAD=3 \
        SPOOF_BIN="$SPOOF" GATEWAY_BIN="$GW" RUN_INDEX="$r" PERF_DATA_CSV="$CSV" \
        ./run_scenario3.sh spoof-wf 30
    COMPONENT=miss SPOOF_ID=0x555 SPOOF_PLAIN_LEN=5 SPOOF_OVERHEAD=3 \
        SPOOF_BIN="$SPOOF" GATEWAY_BIN="$GW" RUN_INDEX="$r" PERF_DATA_CSV="$CSV" \
        ./run_scenario3.sh spoof-wf 30
done

echo
echo "[campanha] PRONTO -> $CSV"
for c in hit miss; do
    awk -F';' -v c="$c" '$2==c && $5=="reached_mac"{s+=$6;n++} \
        END{printf "  %-4s reached_mac medio: %.0f\n", c, (n?s/n:0)}' "$CSV"
done
