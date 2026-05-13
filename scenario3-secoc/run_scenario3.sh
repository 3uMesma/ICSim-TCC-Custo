# Cada execução:
#   1) Sobe secoc_sender  (vcan_trust -> vcan0) em background
#   2) Sobe secoc_gateway (vcan0 -> vcan1) em background — alvo do perf
#   3) Anexa `perf stat` ao PID do gateway
#   4) Dispara o ataque escolhido contra vcan0 por --duration segundos
#   5) Finaliza tudo em ordem, coleta relatório do gateway e CSV do perf
#
# Ataques suportados: dos-py | fuzzing | replay | spoofing | dos-cangen | idle
#
set -euo pipefail
export LC_NUMERIC=C
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/probes.sh"  # wait_perf_attached, wait_proc_sleeping

ATTACK="${1:-}"
DURATION="${2:-30}"
shift $(( $# < 2 ? $# : 2 ))
EXTRA_GATEWAY_FLAGS=("$@")

if [[ -z "$ATTACK" ]]; then
    echo "uso: $0 <dos-py|fuzzing|replay|spoofing|dos-cangen|idle> [duration_s] [flags]"
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

# Helper compartilhado — define o formato canônico do CSV de saída.
. "$HERE/../lib/perf_csv.sh"
PERF_DATA_CSV="${PERF_DATA_CSV:-$HERE/results/perf_data.csv}"
RUN_INDEX="${RUN_INDEX:-1}"

# Higiene: mata instâncias anteriores de sender/gateway para evitar
# contaminação por processo fantasma (um problema anterior)
pkill -9 -f 'secoc_sender|secoc_gateway' 2>/dev/null || true
sleep 0.3

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s gateway_flags=${EXTRA_GATEWAY_FLAGS[*]:-(none)}"

# Garantir que os três vcans existem
"$HERE/setup_vcan_triple.sh" >/dev/null

# Subir sender e gateway em background
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

# perf stat anexado ao gateway (alvo principal da medição)
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"

PERF_GW_RAW="$RESULTS/perf_gateway.raw"
LC_NUMERIC=C perf stat -p "$GW_PID" \
    -e "$PERF_EVENTS" \
    -x ';' -o "$PERF_GW_RAW" \
    -- sleep "$DURATION" &
PERF_PID=$!

# perf também do sender, para decompor o custo total do "SecOC" em autenticação vs verificação
PERF_SENDER_RAW="$RESULTS/perf_sender.raw"
LC_NUMERIC=C perf stat -p "$SENDER_PID" \
    -e "$PERF_EVENTS" \
    -x ';' -o "$PERF_SENDER_RAW" \
    -- sleep "$DURATION" &
PERF_SENDER_PID=$!

# esperar perf abrir counters em ambos antes do ataque.
wait_perf_attached "$PERF_PID" || true
wait_perf_attached "$PERF_SENDER_PID" || true

# Disparar ataque
case "$ATTACK" in
    idle)
        echo "[info] baseline passivo; aguardando $DURATION s"
        sleep "$DURATION"
        ;;

    dos-py)
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

    dos-cangen)
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

# Encerrar perf, gateway e sender em ordem
wait "$PERF_PID"         2>/dev/null || true
wait "$PERF_SENDER_PID"  2>/dev/null || true
kill -INT "$GW_PID"      2>/dev/null || true
kill -INT "$SENDER_PID"  2>/dev/null || true
wait "$GW_PID"           2>/dev/null || true
wait "$SENDER_PID"       2>/dev/null || true

perf_csv_append_raw "$PERF_GW_RAW"     "$PERF_DATA_CSV" \
    cen3 gateway "$ATTACK" "$RUN_INDEX"
perf_csv_append_raw "$PERF_SENDER_RAW" "$PERF_DATA_CSV" \
    cen3 sender  "$ATTACK" "$RUN_INDEX"

echo "[ok] experimento concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= gateway (resumo) ======="
tail -n 30 "$GW_LOG"
echo
echo "======= sender (resumo) ======="
tail -n 15 "$SENDER_LOG"