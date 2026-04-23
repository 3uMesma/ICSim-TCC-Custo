# Cada execução:
#   1) Sobe secoc_sender  (vcan_trust -> vcan0) em background
#   2) Sobe secoc_gateway (vcan0 -> vcan1) em background — alvo do perf
#   3) Anexa `perf stat` ao PID do gateway
#   4) Dispara o ataque escolhido contra vcan0 por --duration segundos
#   5) Finaliza tudo em ordem, coleta relatório do gateway e CSV do perf
#
# Ataques suportados: dos | fuzzing | replay | spoofing | cangen | idle
#
set -euo pipefail
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

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

# Higiene: mata instâncias anteriores de sender/gateway para evitar
# contaminação por processo fantasma (um problema anterior)
pkill -9 -f 'secoc_sender|secoc_gateway' 2>/dev/null || true
sleep 0.3

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s gateway_flags=${EXTRA_GATEWAY_FLAGS[*]:-(none)}"

# -----------------------------------------------------------------------------
# 1) Garantir que os três vcans existem
# -----------------------------------------------------------------------------
"$HERE/setup_vcan_triple.sh" >/dev/null

# -----------------------------------------------------------------------------
# 2) Subir sender e gateway em background
# -----------------------------------------------------------------------------
cleanup_and_die() {
    local msg="$1"; local code="${2:-9}"
    echo "[erro] $msg"
    kill "${SENDER_PID:-}" "${GW_PID:-}" "${PERF_PID:-}" "${PERF_SENDER_PID:-}" 2>/dev/null || true
    exit "$code"
}

SENDER_LOG="$RESULTS/sender.log"
GW_LOG="$RESULTS/gateway.log"

"$HERE/secoc_sender" -i vcan_trust -o vcan0 >"$SENDER_LOG" 2>&1 &
SENDER_PID=$!
sleep 0.2

"$HERE/secoc_gateway" -i vcan0 -o vcan1 "${EXTRA_GATEWAY_FLAGS[@]}" >"$GW_LOG" 2>&1 &
GW_PID=$!
sleep 0.3

if ! kill -0 "$SENDER_PID" 2>/dev/null; then
    echo "[erro] sender morreu na inicialização. Verifique $SENDER_LOG"
    cat "$SENDER_LOG"; exit 3
fi
if ! kill -0 "$GW_PID" 2>/dev/null; then
    echo "[erro] gateway morreu na inicialização. Verifique $GW_LOG"
    cat "$GW_LOG"; kill "$SENDER_PID" 2>/dev/null || true; exit 3
fi
echo "[info] sender PID=$SENDER_PID  gateway PID=$GW_PID"

# -----------------------------------------------------------------------------
# 3) perf stat anexado ao gateway (alvo principal da medição)
# -----------------------------------------------------------------------------
PERF_CSV="$RESULTS/perf.csv"
perf stat -p "$GW_PID" \
    -e cycles,instructions,cache-misses,cache-references,context-switches,task-clock \
    -x ',' -o "$PERF_CSV" \
    -- sleep "$DURATION" &
PERF_PID=$!

# Opcional: perf também do sender, para decompor o custo total do "SecOC".
PERF_SENDER_CSV="$RESULTS/perf_sender.csv"
perf stat -p "$SENDER_PID" \
    -e cycles,instructions,cache-misses,cache-references,context-switches,task-clock \
    -x ',' -o "$PERF_SENDER_CSV" \
    -- sleep "$DURATION" &
PERF_SENDER_PID=$!

# -----------------------------------------------------------------------------
# 4) Disparar ataque
# -----------------------------------------------------------------------------
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
        # Para o Cenário 3, capturamos justamente os quadros *autenticados*
        # produzidos pelo sender em vcan0. O replay desses quadros
        # autenticados deveria falhar por Freshness Value — exatamente a
        # defesa que o SecOC adiciona sobre o Cenário 2.
        CAP="$RESULTS/capture.log"
        echo "[replay] fase 1/2: gravando 3 s de vcan0 (frames autenticados)..." \
            | tee -a "$RESULTS/attack.log"
        python3 "$ATAQUES/Replay-attack.py" record \
            --iface vcan0 --out "$CAP" --record-time 3 \
            >>"$RESULTS/attack.log" 2>&1 || true

        captured_count=0
        [[ -f "$CAP" ]] && captured_count="$(grep -c '^(' "$CAP" || true)"
        if [[ "$captured_count" -lt 5 ]]; then
            FALLBACK="$HERE/../captura.log"
            if [[ -r "$FALLBACK" ]]; then
                echo "[replay] captura com $captured_count frames (insuficiente) — usando $FALLBACK (sem MAC)" \
                    | tee -a "$RESULTS/attack.log"
                sed 's/) can0 /) vcan0 /' "$FALLBACK" > "$CAP"
            else
                cleanup_and_die "captura vazia e captura.log indisponível" 5
            fi
        else
            echo "[replay] captura OK ($captured_count frames autenticados)" \
                | tee -a "$RESULTS/attack.log"
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
        wait "$CANGEN_PID" 2>/dev/null || true
        ;;

    *)
        cleanup_and_die "ataque desconhecido: $ATTACK" 4
        ;;
esac

# -----------------------------------------------------------------------------
# 5) Encerrar perf, gateway e sender em ordem
# -----------------------------------------------------------------------------
wait "$PERF_PID"         2>/dev/null || true
wait "$PERF_SENDER_PID"  2>/dev/null || true
kill -INT "$GW_PID"      2>/dev/null || true
kill -INT "$SENDER_PID"  2>/dev/null || true
wait "$GW_PID"           2>/dev/null || true
wait "$SENDER_PID"       2>/dev/null || true

echo "[ok] experimento concluído."
echo
echo "======= perf GATEWAY ======="
sed '/^#/d' "$PERF_CSV" | column -t -s ','
echo
echo "======= perf SENDER ======="
sed '/^#/d' "$PERF_SENDER_CSV" | column -t -s ','
echo
echo "======= gateway (resumo) ======="
tail -n 30 "$GW_LOG"
echo
echo "======= sender (resumo) ======="
tail -n 15 "$SENDER_LOG"