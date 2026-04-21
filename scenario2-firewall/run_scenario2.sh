# Cada execução:
#   1) Sobe o gateway em background apontando vcan0 -> vcan1
#   2) Anexa `perf stat` ao PID do gateway
#   3) Dispara o ataque escolhido contra vcan0 por --duration segundos
#   4) Finaliza tudo, coleta o relatório do gateway e o CSV do perf
#
# Uso:
#   sudo ./run_scenario2.sh <attack> [duration_s] [extra_gateway_flags...]
#
# Ataques suportados: dos | fuzzing | replay | spoofing | cangen | idle
#   - "idle" roda sem ataque (baseline passivo da carga do gateway)
#   - "cangen" usa a ferramenta nativa do can-utils
# 
set -euo pipefail

ATTACK="${1:-}"
DURATION="${2:-30}"
shift $(( $# < 2 ? $# : 2 ))
EXTRA_GATEWAY_FLAGS=("$@")

if [[ -z "$ATTACK" ]]; then
    echo "uso: $0 <dos|fuzzing|replay|spoofing|cangen|idle> [duration_s] [flags]"
    exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "[erro] precisa de root para perf e para tráfego CAN."
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATAQUES="$HERE/../scripts-attacks"
RESULTS="$HERE/results/$(date +%Y%m%d-%H%M%S)-${ATTACK}"
mkdir -p "$RESULTS"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s"

# Garantir que os vcans existem
"$HERE/setup_vcan_dual.sh" >/dev/null

# Subir gateway em background e capturar PID
GW_LOG="$RESULTS/gateway.log"
"$HERE/gateway" -i vcan0 -o vcan1 "${EXTRA_GATEWAY_FLAGS[@]}" >"$GW_LOG" 2>&1 &
GW_PID=$!
sleep 0.3

if ! kill -0 "$GW_PID" 2>/dev/null; then
    echo "[erro] gateway morreu na inicialização. Verifique $GW_LOG"
    cat "$GW_LOG"
    exit 3
fi
echo "[info] gateway rodando com PID $GW_PID"

# perf stat anexado ao gateway
PERF_CSV="$RESULTS/perf.csv"
perf stat -p "$GW_PID" \
    -e cycles,instructions,cache-misses,cache-references,context-switches,task-clock \
    -x ',' -o "$PERF_CSV" \
    -- sleep "$DURATION" &
PERF_PID=$!

# Disparar ataque em paralelo
case "$ATTACK" in
    idle)
        echo "[info] baseline passivo; aguardando $DURATION s"
        sleep "$DURATION"
        ;;
    dos)
        python3 "$ATAQUES/DoS-attack.py" --iface vcan0 --duration "$DURATION" --rate 0 \
            >"$RESULTS/attack.log" 2>&1
        ;;
    fuzzing)
        python3 "$ATAQUES/Fuzzy-attack.py" --iface vcan0 --duration "$DURATION" \
            >"$RESULTS/attack.log" 2>&1
        ;;
    replay)
        # Replay tem dois estágios: capturar tráfego legítimo (record) e
        # depois re-injetá-lo (replay). Se ninguém estiver gerando tráfego
        # em vcan0 (icsim+controls não rodando), cai num log pré-gravado
        # do ICSim para que o experimento ainda produza resultado.
        CAP="$RESULTS/capture.log"
        echo "[replay] fase 1/2: gravando $DURATION s de vcan0..." \
            | tee -a "$RESULTS/attack.log"
        python3 "$ATAQUES/Replay-attack.py" record \
            --iface vcan0 --out "$CAP" --record-time "$DURATION" \
            >>"$RESULTS/attack.log" 2>&1 || true

        if [[ ! -s "$CAP" ]]; then
            FALLBACK="$HERE/../captura.log"
            if [[ -r "$FALLBACK" ]]; then
                echo "[replay] nenhum tráfego legítimo em vcan0 — usando $FALLBACK" \
                    | tee -a "$RESULTS/attack.log"
                sed 's/) can0 /) vcan0 /' "$FALLBACK" > "$CAP"
            else
                echo "[erro] captura vazia e sample-can.log indisponível"
                kill "$GW_PID" "$PERF_PID" 2>/dev/null || true
                exit 5
            fi
        fi

        echo "[replay] fase 2/2: re-injetando por ${DURATION}s (speedup=10x)..." \
            | tee -a "$RESULTS/attack.log"
        python3 "$ATAQUES/Replay-attack.py" replay \
            --iface vcan0 --in "$CAP" --speedup 10 --loops 99999 \
            >>"$RESULTS/attack.log" 2>&1 &
        REPLAY_PID=$!
        sleep "$DURATION"
        kill "$REPLAY_PID" 2>/dev/null || true
        wait "$REPLAY_PID" 2>/dev/null || true
        ;;
    spoofing)
        python3 "$ATAQUES/Spoofing-attack.py" --iface vcan0 --target speed \
            --value 220 --duration "$DURATION" --rate 1 \
            >"$RESULTS/attack.log" 2>&1
        ;;
    cangen)
        cangen vcan0 -I 000 -L 8 -D FFFFFFFFFFFFFFFF -g 0 &
        CANGEN_PID=$!
        sleep "$DURATION"
        kill "$CANGEN_PID" 2>/dev/null || true
        ;;
    *)
        echo "[erro] ataque desconhecido: $ATTACK"
        kill "$GW_PID" "$PERF_PID" 2>/dev/null || true
        exit 4
        ;;
esac

# Encerrar tudo
wait "$PERF_PID" 2>/dev/null || true
kill -INT "$GW_PID" 2>/dev/null || true
wait "$GW_PID"     2>/dev/null || true

echo "[ok] experiment concluído."
echo
echo "======= perf (resumo) ======="
cat "$PERF_CSV" | sed '/^#/d' | column -t -s ','
echo
echo "======= gateway (resumo) ======="
tail -n 30 "$GW_LOG"
