# Cada execução:
#   1) Sobe o gateway em background apontando vcan0 -> vcan1
#   2) Anexa `perf stat` ao PID do gateway
#   3) Dispara o ataque escolhido contra vcan0 por --duration segundos
#   4) Finaliza tudo, coleta o relatório do gateway e o CSV do perf
#
# Ataques suportados: dos-py | fuzzing | replay | spoofing | dos-cangen | idle
#   - "idle" roda sem ataque (baseline passivo da carga do gateway)
#   - "cangen" usa a ferramenta nativa do can-utils
# 
set -euo pipefail
export LC_NUMERIC=C

# espera perf attachar / processo dormir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/probes.sh"

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
COMPONENT="${COMPONENT:-gateway}"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s"

# Garantir que os vcans existem
"$HERE/setup_vcan_dual.sh" >/dev/null

# Subir gateway em background e capturar PID
GW_LOG="$RESULTS/gateway.log"
GATEWAY_BIN="${GATEWAY_BIN:-$HERE/gateway}"
"$GATEWAY_BIN" -i vcan0 -o vcan1 "${EXTRA_GATEWAY_FLAGS[@]}" >"$GW_LOG" 2>&1 &
GW_PID=$!
sleep 0.3

if ! kill -0 "$GW_PID" 2>/dev/null; then
    echo "[erro] gateway morreu na inicialização. Verifique $GW_LOG"
    cat "$GW_LOG"
    exit 3
fi
echo "[info] gateway rodando com PID $GW_PID"

# perf stat anexado ao gateway
PERF_RAW="$RESULTS/perf_gateway.raw"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"
LC_NUMERIC=C perf stat -p "$GW_PID" \
    -e "$PERF_EVENTS" \
    -x ';' -o "$PERF_RAW" \
    -- sleep "$DURATION" &
PERF_PID=$!

# esperar perf abrir counters antes de disparar o ataque.
wait_perf_attached "$PERF_PID" || true

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
        SCRIPT="$ATAQUES/Replay-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"

        # Usa a captura compartilhada da campanha (vinda de master_run.sh
        # via env var REPLAY_LOG)
        CAP="${REPLAY_LOG:-}"
        if [[ -z "$CAP" || ! -s "$CAP" ]]; then
            # Fallback: grava na própria rodada
            CAP="$RESULTS/capture.log"
            echo "[replay] sem REPLAY_LOG compartilhado — gravando..." \
                | tee -a "$RESULTS/attack.log"
            python3 "$SCRIPT" record \
                --iface vcan0 --out "$CAP" --record-time 3 \
                >>"$RESULTS/attack.log" 2>&1 || true

            if [[ ! -s "$CAP" ]]; then
                FALLBACK="$HERE/../captura.log"
                if [[ -r "$FALLBACK" ]]; then
                    echo "[replay] usando fallback: $FALLBACK" \
                        | tee -a "$RESULTS/attack.log"
                    sed 's/) can0 /) vcan0 /' "$FALLBACK" > "$CAP"
                else
                    echo "[erro] captura vazia e fallback indisponível"
                    kill "$GW_PID" "$PERF_PID" 2>/dev/null || true
                    exit 5
                fi
            fi
        else
            n_frames="$(grep -c '^(' "$CAP" 2>/dev/null || echo 0)"
            echo "[replay] usando captura compartilhada: $CAP ($n_frames frames)" \
                | tee -a "$RESULTS/attack.log"
        fi

        echo "[replay] re-injetando por ${DURATION}s (speedup=10x)..." \
            | tee -a "$RESULTS/attack.log"
        python3 "$SCRIPT" replay \
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
        ;;
    legit-flood)
        cangen vcan0 -I 244 -L 5 -g 0 &
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

perf_csv_append_raw "$PERF_RAW" "$PERF_DATA_CSV" \
    cen2 "$COMPONENT" "$ATTACK" "$RUN_INDEX"
echo "[ok] experiment concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= gateway (resumo) ======="
tail -n 30 "$GW_LOG"
